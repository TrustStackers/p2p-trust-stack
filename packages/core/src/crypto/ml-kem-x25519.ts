/**
 * MLKEM768-X25519 hybrid KEM as an `@hpke/core` `KemInterface`.
 *
 * KEM id `0x647a` (draft-ietf-hpke-pq-05) — combines ML-KEM-768 (FIPS 203)
 * with X25519:
 *   enc = concat(mlkem_enc, x25519_enc)
 *   ss  = concat(mlkem_ss,  x25519_ss)
 *
 * This reuses `@hpke/common`'s `XCryptoKey` as a carrier for the raw key bytes
 * (ML-KEM-768 is not a WebCrypto algorithm), following the same pattern as
 * `@hpke/ml-kem`'s `MlKemBase`, but with a standalone implementation so the
 * hybrid's full key material (2432-byte sk / 1216-byte pk) is handled directly.
 */

import {
  XCryptoKey,
  KEM_USAGES,
  isCryptoKeyPair,
  type KemId,
  type KemInterface,
  type RecipientContextParams,
  type SenderContextParams,
} from '@hpke/common';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import {
  generateMlKem768X25519KeyPair,
  mlKem768X25519Encap,
  mlKem768X25519Decap,
  MLKEM768_X25519_PK_BYTES,
  MLKEM768_X25519_SK_BYTES,
  MLKEM768_X25519_ENC_BYTES,
  MLKEM768_X25519_SS_BYTES,
  MLKEM768_X25519_KEM_ID,
} from './pqc.js';

const NAME = 'MLKEM768-X25519';

/**
 * HPKE-Base seal under MLKEM768-X25519, mirroring `hpkeBaseSeal` but taking the
 * recipient's RAW public key (1216 bytes) — the form a peer publishes as
 * `#key-kem` in its DID document.
 *
 * @returns { enc, ciphertext } — `enc` is 1120 bytes (vs 32 for DHKEM(X25519)),
 *          which is why the OPENER must be told which KEM was used.
 */
export async function hpkeHybridSeal(
  recipientRawPublicKey: Uint8Array,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<{ enc: Uint8Array; ciphertext: Uint8Array }> {
  const kem = new MlKem768X25519();
  const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
  const recipientPublicKey = await kem.importKey('raw', toArrayBuffer(recipientRawPublicKey), true);
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ciphertext = new Uint8Array(await sender.seal(plaintext, aad));
  return { enc: new Uint8Array(sender.enc), ciphertext };
}

/**
 * HPKE-Base open under MLKEM768-X25519.
 *
 * @param recipientRawSecretKey  2432-byte secret key (mlkem_sk ‖ x25519_sk)
 * @param recipientRawPublicKey  optional 1216-byte public key; supplied when
 *                               available so the context can be built as a pair
 */
export async function hpkeHybridOpen(
  recipientRawSecretKey: Uint8Array,
  enc: Uint8Array,
  ciphertext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  recipientRawPublicKey?: Uint8Array,
): Promise<Uint8Array> {
  const kem = new MlKem768X25519();
  const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
  const privateKey = await kem.importKey('raw', toArrayBuffer(recipientRawSecretKey), false);
  const recipientKey = recipientRawPublicKey
    ? { publicKey: await kem.importKey('raw', toArrayBuffer(recipientRawPublicKey), true), privateKey }
    : privateKey;
  const recipient = await suite.createRecipientContext({ recipientKey, enc, info });
  return new Uint8Array(await recipient.open(ciphertext, aad));
}

function toBytes(input: ArrayBufferLike | ArrayBufferView): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  return new Uint8Array(input);
}

/** Copy bytes into a fresh plain ArrayBuffer (KemInterface returns ArrayBuffer). */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

export class MlKem768X25519 implements KemInterface {
  readonly id: KemId = MLKEM768_X25519_KEM_ID as unknown as KemId;
  readonly name = NAME;
  readonly secretSize = MLKEM768_X25519_SS_BYTES;
  readonly encSize = MLKEM768_X25519_ENC_BYTES;
  readonly publicKeySize = MLKEM768_X25519_PK_BYTES;
  readonly privateKeySize = MLKEM768_X25519_SK_BYTES;

  async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    const xk = key as XCryptoKey;
    if (xk.type !== 'public') throw new Error(`${NAME}: not a public key`);
    return toArrayBuffer(xk.key);
  }
  async deserializePublicKey(key: ArrayBufferLike | ArrayBufferView): Promise<CryptoKey> {
    return new XCryptoKey(NAME, toBytes(key), 'public', []);
  }
  async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    const xk = key as XCryptoKey;
    if (xk.type !== 'private') throw new Error(`${NAME}: not a private key`);
    return toArrayBuffer(xk.key);
  }
  async deserializePrivateKey(key: ArrayBufferLike | ArrayBufferView): Promise<CryptoKey> {
    return new XCryptoKey(NAME, toBytes(key), 'private', KEM_USAGES);
  }
  async importKey(format: 'raw' | 'jwk', key: ArrayBuffer | JsonWebKey, isPublic = true): Promise<CryptoKey> {
    if (format !== 'raw') throw new Error(`${NAME}: only raw key format is supported`);
    const bytes = key instanceof Uint8Array ? key : new Uint8Array(key as ArrayBuffer);
    return new XCryptoKey(NAME, bytes, isPublic ? 'public' : 'private', isPublic ? [] : KEM_USAGES);
  }
  async generateKeyPair(): Promise<CryptoKeyPair> {
    const kp = generateMlKem768X25519KeyPair();
    return {
      privateKey: new XCryptoKey(NAME, kp.secretKey, 'private', KEM_USAGES),
      publicKey: new XCryptoKey(NAME, kp.publicKey, 'public', []),
    };
  }
  async deriveKeyPair(_ikm: ArrayBufferLike | ArrayBufferView): Promise<CryptoKeyPair> {
    // Deterministic derivation from ikm is not implemented; HPKE flows use
    // generateKeyPair(), not deriveKeyPair(). Generate a fresh key pair instead.
    return this.generateKeyPair();
  }
  async encap(params: SenderContextParams): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    const pk = toBytes(await this.serializePublicKey(params.recipientPublicKey));
    const { enc, sharedSecret } = mlKem768X25519Encap(pk);
    return { sharedSecret: toArrayBuffer(sharedSecret), enc: toArrayBuffer(enc) };
  }
  async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const enc = toBytes(params.enc);
    const rSk = isCryptoKeyPair(params.recipientKey) ? params.recipientKey.privateKey : params.recipientKey;
    const sk = toBytes(await this.serializePrivateKey(rSk));
    const ss = mlKem768X25519Decap(enc, sk);
    return toArrayBuffer(ss);
  }
}
