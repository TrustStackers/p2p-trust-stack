/**
 * TSP v3 (Rev 3) message sealing and opening.
 *
 * ## Wire format
 *
 *   -E## <version 8> <VID_sndr> <VID_rcvr|4BAA> <payload> <signature>
 *
 * where the signable portion is `version + VID_sndr + VID_rcvr + payload`
 * (everything between the `-E##` counter and the signature), and the signature
 * is a CESR attachment group:
 *
 *   -C## -K## <Indexer(A + index + 86-char Ed25519 sig)>
 *
 * The payload is a `-Z##` group whose first field is an X-tag (XSCS/XRFI/XRFA/XRFD):
 *
 *   -Z## XSCS <4BAA> <4BAA> -A## <body primitive>          (application)
 *   -Z## XRFI <4BAA> <Digest> <Nonce> -JAA -JAA <4BAA>      (invite)
 *   -Z## XRFA <4BAA> <Digest> <Reply_Digest> <4BAA>         (accept)
 *   -Z## XRFD <4BAA> <Digest> <4BAA>                        (decline)
 */

import { Matter, Counter, Indexer } from 'cesr';
import { cesrEncode, CESR_CODES } from '../../crypto/cesr.js';
import { signEd25519, verifyEd25519, sha256, ED25519_SECRET_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES } from '../../crypto/primitives.js';
import {
  mlDsa65Sign,
  mlDsa65Verify,
  ML_DSA_65_SK_BYTES,
  ML_DSA_65_PK_BYTES,
  encodeMlDsa65Signature,
  decodeMlDsa65Signature,
} from '../../crypto/pqc.js';
import {
  encodeEnvelopeTag,
  encodePayloadTag,
  encodeNonce,
  encodeHpkeBaseCipher,
  decodeHpkeBaseCipher,
  NONCE_BYTES,
} from '../../crypto/cesr-v2.js';
import {
  encodeVid,
  NULL_VID,
  encodeDigestSha256,
  TSP_FIELD_SCS,
  TSP_FIELD_RFI,
  TSP_FIELD_RFA,
  TSP_FIELD_RFD,
} from '../fields.js';
import { TSP_CURRENT_VERSION_STRING } from '../version.js';
import type { DidDocument } from '../../did/types.js';
import type { TspSealParams, TspOpenParams, TspEnvelope, TspPayload, TspRfiPayload, TspRfaPayload, Vid } from './types.js';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
function text(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}
function quadlets(s: string): number {
  if (s.length % 4 !== 0) {
    throw new Error(`quadlets: string length ${s.length} is not quadlet-aligned`);
  }
  return s.length / 4;
}

/** Peek the leading CESR counter; returns code, count and header length. */
function peekCounter(t: string): { code: string; count: number; n: number } {
  let peek: ReturnType<typeof Counter.peek>;
  try {
    peek = Counter.peek(utf8(t));
  } catch {
    throw new SyntaxError(`peekCounter: not a counter: ${JSON.stringify(t.slice(0, 8))}`);
  }
  if (!peek.frame) {
    throw new SyntaxError(`peekCounter: not a counter: ${JSON.stringify(t.slice(0, 8))}`);
  }
  return { code: peek.frame.code, count: peek.frame.count, n: peek.n };
}

/** Peek the leading CESR matter primitive; returns code, raw bytes and length. */
function peekMatter(t: string): { code: string; raw: Uint8Array; n: number } {
  let peek: ReturnType<typeof Matter.peek>;
  try {
    peek = Matter.peek(utf8(t));
  } catch {
    throw new SyntaxError(`peekMatter: not a matter primitive: ${JSON.stringify(t.slice(0, 8))}`);
  }
  if (!peek.frame) {
    throw new SyntaxError(`peekMatter: not a matter primitive: ${JSON.stringify(t.slice(0, 8))}`);
  }
  return { code: peek.frame.code, raw: new Uint8Array(peek.frame.raw), n: peek.n };
}

/**
 * The EMPTY routing-field form: `Reply_Path` and `Referral_Field` are written as
 * `-JAA` — a `-J` counter with count 0 — because this implementation only
 * supports DIRECT messages (no reply path, no referral).
 *
 * Three sites depend on that assumption and are kept in lockstep through this
 * one constant: `encodePayload()` writes it, `computeSaidDigest()` covers it in
 * the SAID, and `decodePayload()` advances past it. TSP rev 3 does define
 * non-empty `-J##` routing groups; a digest computed over the empty form while
 * the decoder advanced over a non-empty one would disagree about the very
 * message it authenticates. Implementing routing means threading the real value
 * through all three — not just one.
 */
const EMPTY_ROUTING_FIELD = '-JAA';

/**
 * Advance past a routing field, refusing — loudly — to walk a non-empty one.
 *
 * The decoder used to hard-code a 4-byte stride here. That is correct only while
 * the field is empty; the moment it carried a `-J##` group with content, the
 * decoder would silently mis-slice everything after it — including the inlined
 * DID document, which `parseDidDocument` would then be fed as garbage. A silent
 * misparse in the handshake is the failure class this effort exists to remove,
 * so an unsupported routing field is a named throw, never a guess.
 *
 * Exported for unit testing (same rationale as `assertSignableWithinLimit`): a
 * test can pin the advance and both rejection paths without having to construct
 * a signed message carrying routing, which the encoder deliberately cannot emit.
 */
export function advanceRoutingField(fields: string, off: number, name: string): number {
  const probe = peekCounter(fields.slice(off));

  if (probe.count !== 0) {
    throw new SyntaxError(
      `decodePayload: ${name} carries ${probe.count} quadlet(s) of routing data, which this ` +
      `implementation does not support — only direct messages with an empty ${name} are handled. ` +
      `Refusing to mis-slice the remainder of the payload.`,
    );
  }
  if (probe.code !== '-J') {
    throw new SyntaxError(
      `decodePayload: expected ${JSON.stringify(name)} to be an empty -J## routing counter ` +
      `(${JSON.stringify(EMPTY_ROUTING_FIELD)}), found counter ${JSON.stringify(probe.code)} ` +
      `at offset ${off}`,
    );
  }
  return off + probe.n;
}

/**
 * True when a peeked counter code is one of the given counter letters, in
 * EITHER form: the small 4-char form (`-E##`) or the Big 8-char form
 * (`--E#####`).
 *
 * CESR 2.0 emits the Big form automatically once the count exceeds 4095
 * quadlets (16 380 chars), which ANY TSP message over ~10.7 KB hits (both VIDs
 * are long-form `did:peer:4` strings). Comparing the raw code with
 * `startsWith('-E')` therefore REJECTED the encoder's own output: the receiver
 * could neither peek nor open the message, dropped it silently, and the sender
 * timed out after 30 s. `peek.n` and `peek.count` are correct for either form,
 * so only the code test needed widening.
 */
function isCounterFamily(code: string, letter: string): boolean {
  return code === `-${letter}` || code === `--${letter}`;
}

/**
 * Seal-time sanity bound on the signable portion (`version + VID_sndr +
 * VID_rcvr + payload`), in CESR text characters. The Big counter form can
 * represent far more, so this is not a wire-format limit — it is a guard
 * against emitting a single multi-megabyte TSP message by accident.
 *
 * Note the effective END-TO-END ceiling is lower and belongs to the transport:
 * `Libp2pTransport` refuses a sealed frame larger than its `maxMessageBytes`
 * (default `DEFAULT_MAX_MESSAGE_BYTES` = 1 MiB) with a `TransportFrameTooLargeError`,
 * so ~1 MiB sealed (≈750 KB of body) is today's practical maximum. The largest
 * legitimate payloads in this stack (identity_push with every credential,
 * VTC/VMC fan-out, governance docs) are well under 100 KB.
 */
export const TSP_MAX_SIGNABLE_CHARS = 4 * 1024 * 1024;

/**
 * Throw when a signable portion exceeds {@link TSP_MAX_SIGNABLE_CHARS}.
 * Extracted so the bound is unit-testable without building a multi-MB message.
 */
export function assertSignableWithinLimit(signableChars: number): void {
  if (signableChars > TSP_MAX_SIGNABLE_CHARS) {
    throw new RangeError(
      `tspSeal: signable portion is ${signableChars} chars, over the ` +
      `${TSP_MAX_SIGNABLE_CHARS}-char limit for a single TSP message`,
    );
  }
}

function encodeVidStr(vid: Vid): string {
  return encodeVid(utf8(vid));
}

/** Wrap a quadlet-aligned CESR string in a `-A##` generic group. */
function genericGroup(content: string): string {
  return Counter.v2.GenericGroup(quadlets(content)).text() + content;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** HPKE `info` input for TSP (5 bytes). */
export const TSP_HPKE_INFO = new TextEncoder().encode('YTSP-');

/**
 * HPKE encapsulated-key size for DHKEM(X25519) — the KEM this deployment seals
 * confidential messages with (`hpkeBaseSeal` over the peer's X25519 key).
 *
 * The MLKEM768-X25519 hybrid uses 1120 (`MLKEM768_X25519_ENC_BYTES`). The CESR
 * HPKE-Base cipher primitive carries NO KEM identifier, so the split point cannot
 * be inferred from the bytes on the wire — the receiver must know which KEM the
 * message was sealed under. `tspOpen` therefore takes an optional
 * `hpkeEncSize` for a future PQ deployment rather than guessing, which is why
 * this is a named constant and not a literal.
 */
export const X25519_ENC_SIZE = 32;

/**
 * Compute the HPKE `aad` = CONCAT(TSP_Version, VID_sndr, VID_rcvr) as CESR
 * octets. Used by the relationship layer before sealing/opening confidential
 * messages.
 */
export function encodeAad(vidSender: Vid, vidReceiver: Vid | null): Uint8Array {
  const vidSndr = encodeVidStr(vidSender);
  const vidRcvr = vidReceiver ? encodeVidStr(vidReceiver) : NULL_VID;
  return utf8(TSP_CURRENT_VERSION_STRING + vidSndr + vidRcvr);
}

// ---------------------------------------------------------------------------
// Self-addressing digest (spec 7.2.1)
// ---------------------------------------------------------------------------

/** Binary (B-domain) form of a CESR matter primitive. */
function binaryOfMatter(t: string): Uint8Array {
  let peek: ReturnType<typeof Matter.peek>;
  try {
    peek = Matter.peek(utf8(t));
  } catch {
    throw new SyntaxError(`binaryOfMatter: not a matter primitive: ${JSON.stringify(t.slice(0, 8))}`);
  }
  if (!peek.frame) {
    throw new SyntaxError(`binaryOfMatter: not a matter primitive: ${JSON.stringify(t.slice(0, 8))}`);
  }
  return new Uint8Array(peek.frame.binary());
}

/** Binary (B-domain) form of a CESR counter. */
function binaryOfCounter(t: string): Uint8Array {
  let peek: ReturnType<typeof Counter.peek>;
  try {
    peek = Counter.peek(utf8(t));
  } catch {
    throw new SyntaxError(`binaryOfCounter: not a counter: ${JSON.stringify(t.slice(0, 8))}`);
  }
  if (!peek.frame) {
    throw new SyntaxError(`binaryOfCounter: not a counter: ${JSON.stringify(t.slice(0, 8))}`);
  }
  return new Uint8Array(peek.frame.binary());
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/**
 * 33 bytes of 0x23 — the dummy filling the digest's own slot during SAID
 * derivation (spec 7.2.1): the full binary length of a SHA2-256 digest
 * primitive (1 code byte + 32 digest bytes).
 */
const DIGEST_DUMMY: Uint8Array = new Uint8Array(33).fill(0x23);

/**
 * Compute the self-addressing TSP digest (spec 7.2.1) of a relationship-forming
 * payload: the SHA2-256 of the binary serialization of the envelope prefix
 * (TSP_Version, VID_sndr, VID_rcvr) followed by the payload fields, with the
 * digest's own slot filled with the 0x23 dummy and the `-E##`/`-Z##` framing
 * tags and the Padding_Field excluded.
 *
 * - `RFI`: the invite's own `Digest` is derived (slot filled with dummy); the
 *   nonce, Reply_Path and Referral_Field are covered.
 * - `RFA`: the `Digest` is the echoed request digest (copied verbatim) and the
 *   `Reply_Digest` is derived (slot filled with dummy).
 */
export function computeSaidDigest(
  kind: 'RFI' | 'RFA',
  vidSender: Vid,
  vidReceiver: Vid | null,
  fields: { nonce?: Uint8Array; requestDigest?: Uint8Array },
): Uint8Array {
  const version = TSP_CURRENT_VERSION_STRING;
  const vidSndr = encodeVidStr(vidSender);
  const vidRcvr = vidReceiver ? encodeVidStr(vidReceiver) : NULL_VID;

  const parts: Uint8Array[] = [
    binaryOfMatter(version),
    binaryOfMatter(vidSndr),
    binaryOfMatter(vidRcvr),
    binaryOfMatter(kind === 'RFI' ? TSP_FIELD_RFI : TSP_FIELD_RFA),
    binaryOfMatter(NULL_VID), // sender identity in payload (NULL for a direct message)
  ];

  if (kind === 'RFI') {
    if (!fields.nonce) throw new Error('computeSaidDigest: RFI requires a nonce');
    parts.push(
      DIGEST_DUMMY,
      binaryOfMatter(encodeNonce(fields.nonce)),
      // Routing is covered in its EMPTY form only — see EMPTY_ROUTING_FIELD.
      // A non-empty routing field cannot reach here: the decoder rejects one
      // (advanceRoutingField) and the encoder cannot produce one.
      binaryOfCounter(EMPTY_ROUTING_FIELD), // Reply_Path (empty = direct)
      binaryOfCounter(EMPTY_ROUTING_FIELD), // Referral_Field (empty = not a referral)
    );
  } else {
    if (!fields.requestDigest) throw new Error('computeSaidDigest: RFA requires the request digest');
    parts.push(
      binaryOfMatter(encodeDigestSha256(fields.requestDigest)),
      DIGEST_DUMMY, // Reply_Digest slot
    );
  }

  return sha256(concatBytes(...parts));
}

// ---------------------------------------------------------------------------
// Payload encode
// ---------------------------------------------------------------------------

function encodePayload(payload: TspPayload): string {
  let fields: string;

  switch (payload.type) {
    case 'TSP_GEN': {
      const bodyPrim = cesrEncode(CESR_CODES.VARIABLE_BYTES, payload.body);
      const stream = genericGroup(bodyPrim);
      fields = TSP_FIELD_SCS + NULL_VID + NULL_VID + stream;
      break;
    }
    case 'TSP_RFI': {
      const digest = encodeDigestSha256(payload.digest!);
      const nonce = encodeNonce(payload.nonce);
      fields = TSP_FIELD_RFI + NULL_VID + digest + nonce
        + EMPTY_ROUTING_FIELD + EMPTY_ROUTING_FIELD + NULL_VID;
      if (payload.didDocument) {
        fields += cesrEncode(CESR_CODES.VARIABLE_BYTES, new TextEncoder().encode(JSON.stringify(payload.didDocument)));
      }
      break;
    }
    case 'TSP_RFA': {
      const digest = encodeDigestSha256(payload.digest);
      const replyDigest = encodeDigestSha256(payload.replyDigest!);
      fields = TSP_FIELD_RFA + NULL_VID + digest + replyDigest + NULL_VID;
      if (payload.didDocument) {
        fields += cesrEncode(CESR_CODES.VARIABLE_BYTES, new TextEncoder().encode(JSON.stringify(payload.didDocument)));
      }
      break;
    }
    case 'TSP_RFD': {
      const digest = encodeDigestSha256(payload.digest);
      fields = TSP_FIELD_RFD + NULL_VID + digest + NULL_VID;
      break;
    }
    case 'TSP_GEN_CONFIDENTIAL': {
      // Confidential payloads carry a single HPKE-Base cipher primitive
      // (`4F/5F/6F` wrapping enc || ct), not a -Z## group.
      return encodeHpkeBaseCipher(concat(payload.enc, payload.ciphertext));
    }
    default:
      throw new Error(`encodePayload: unsupported payload type`);
  }

  return encodePayloadTag(quadlets(fields)) + fields;
}

// ---------------------------------------------------------------------------
// Payload decode
// ---------------------------------------------------------------------------

function parseDidDocument(text: string): DidDocument {
  const peek = peekMatter(text);
  return JSON.parse(new TextDecoder().decode(peek.raw)) as DidDocument;
}

function decodePayload(payloadText: string, hpkeEncSize: number = X25519_ENC_SIZE): TspPayload {
  // Confidential payloads are a single HPKE-Base cipher primitive (4F/5F/6F),
  // not a -Z## group.
  if (!payloadText.startsWith('-')) {
    const cipher = decodeHpkeBaseCipher(payloadText);
    if (cipher.length <= hpkeEncSize) {
      // Guard: a short cipher used to be sliced at a fixed offset, silently
      // returning a truncated `enc` and an empty/garbage `ciphertext`. Fail loudly
      // instead, and say which KEM size was assumed.
      throw new SyntaxError(
        `decodePayload: HPKE-Base cipher is ${cipher.length} bytes, which cannot hold a ` +
        `${hpkeEncSize}-byte encapsulated key plus ciphertext (assumed KEM enc size ` +
        `${hpkeEncSize}; pass tspOpen({ hpkeEncSize }) for MLKEM768-X25519 = 1120)`,
      );
    }
    const enc = cipher.slice(0, hpkeEncSize);
    const ciphertext = cipher.slice(hpkeEncSize);
    return { type: 'TSP_GEN_CONFIDENTIAL', enc, ciphertext };
  }

  const p = peekCounter(payloadText); // -Z##
  const fields = payloadText.slice(p.n);
  const tag = fields.slice(0, 4);

  if (tag === TSP_FIELD_SCS) {
    let off = 4;
    off = peekMatter(fields.slice(off)).n + off; // VID_sndr (4BAA)
    off = peekMatter(fields.slice(off)).n + off; // padding (4BAA)
    const g = peekCounter(fields.slice(off)); // -A##
    const groupContent = fields.slice(off + g.n, off + g.n + g.count * 4);
    const bodyPeek = peekMatter(groupContent);
    return { type: 'TSP_GEN', body: bodyPeek.raw };
  }

  if (tag === TSP_FIELD_RFI) {
    let off = 4;
    off = peekMatter(fields.slice(off)).n + off; // VID_sndr
    const digestPeek = peekMatter(fields.slice(off));
    const digest = digestPeek.raw;
    off += digestPeek.n;
    const noncePeek = peekMatter(fields.slice(off));
    const nonce = noncePeek.raw;
    off += noncePeek.n;
    // Routing fields are advanced by their ACTUAL encoded length, and a
    // non-empty one is rejected loudly rather than mis-sliced — see
    // advanceRoutingField(). The old code stepped a hard-coded 4 bytes here.
    off = advanceRoutingField(fields, off, 'Reply_Path');
    off = advanceRoutingField(fields, off, 'Referral_Field');
    off = peekMatter(fields.slice(off)).n + off; // Padding (4BAA)
    const didDocument = off < fields.length ? parseDidDocument(fields.slice(off)) : undefined;
    return { type: 'TSP_RFI', nonce, digest, didDocument };
  }

  if (tag === TSP_FIELD_RFA) {
    let off = 4;
    off = peekMatter(fields.slice(off)).n + off; // VID_sndr
    const digestPeek = peekMatter(fields.slice(off));
    const digest = digestPeek.raw;
    off += digestPeek.n;
    const replyDigestPeek = peekMatter(fields.slice(off));
    const replyDigest = replyDigestPeek.raw;
    off += replyDigestPeek.n;
    off = peekMatter(fields.slice(off)).n + off; // Padding (4BAA)
    const didDocument = off < fields.length ? parseDidDocument(fields.slice(off)) : undefined;
    return { type: 'TSP_RFA', digest, replyDigest, didDocument };
  }

  if (tag === TSP_FIELD_RFD) {
    let off = 4;
    off = peekMatter(fields.slice(off)).n + off; // VID_sndr
    const digest = peekMatter(fields.slice(off)).raw;
    return { type: 'TSP_RFD', digest };
  }

  throw new SyntaxError(`decodePayload: unknown field tag ${JSON.stringify(tag)}`);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Decode a quadlet-aligned CESR text string to its binary (B-domain) form.
 * TSP messages are entirely base64url, so this is a naive base64url decode.
 */
function cesrTextToBinary(s: string): Uint8Array {
  if (s.length % 4 !== 0) {
    throw new Error(`cesrTextToBinary: string length ${s.length} is not quadlet-aligned`);
  }
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

/**
 * Sign the binary envelope (the `-E##` frame plus its signable content),
 * choosing Ed25519 or ML-DSA-65 by key length. Per spec 9.5, the signature
 * authenticates the exact encoded binary bytes, including the `-E##` frame.
 *
 * The algorithm is selected by length because the wire format carries no
 * algorithm identifier for the sender's key; the error names what IS supported so
 * an unexpected (e.g. rotated / wrong-slot) key is diagnosable from the message.
 */
function signMessage(signable: Uint8Array, secretKey: Uint8Array): string {
  if (secretKey.length === ED25519_SECRET_KEY_BYTES) {
    return Indexer.crypto.ed25519_sig(signEd25519(signable, secretKey), 0).text();
  }
  if (secretKey.length === ML_DSA_65_SK_BYTES) {
    return encodeMlDsa65Signature(mlDsa65Sign(signable, secretKey));
  }
  throw new Error(
    `signMessage: unsupported signing key length ${secretKey.length} — supported: ` +
    `${ED25519_SECRET_KEY_BYTES} (Ed25519), ${ML_DSA_65_SK_BYTES} (ML-DSA-65)`,
  );
}

/**
 * Verify a signature over the binary envelope, choosing the algorithm by key
 * length (see `signMessage`).
 *
 * Throws for an unsupported length rather than returning false: that is a key
 * resolution/config error, not a bad signature, and conflating the two would
 * report a valid peer as an impostor.
 */
function verifyMessage(sigBytes: Uint8Array, signable: Uint8Array, publicKey: Uint8Array): boolean {
  if (publicKey.length === ED25519_PUBLIC_KEY_BYTES) {
    return verifyEd25519(sigBytes, signable, publicKey);
  }
  if (publicKey.length === ML_DSA_65_PK_BYTES) {
    return mlDsa65Verify(sigBytes, signable, publicKey);
  }
  throw new Error(
    `verifyMessage: unsupported public key length ${publicKey.length} — supported: ` +
    `${ED25519_PUBLIC_KEY_BYTES} (Ed25519), ${ML_DSA_65_PK_BYTES} (ML-DSA-65). ` +
    `The peer's verification key does not match the key it signs with`,
  );
}

/** Build the signable portion and sign it. Returns the full CESR message bytes. */
export function tspSeal(params: TspSealParams): Uint8Array {
  const { vidSender, vidReceiver, payload, signingSecretKey } = params;

  const version = TSP_CURRENT_VERSION_STRING;
  const vidSndr = encodeVidStr(vidSender);
  const vidRcvr = vidReceiver ? encodeVidStr(vidReceiver) : NULL_VID;

  // Relationship-forming payloads carry a self-addressing digest, derived here
  // (never trusted from the caller) so the wire bytes are always spec-conformant.
  let resolvedPayload = payload;
  if (payload.type === 'TSP_RFI') {
    resolvedPayload = {
      ...payload,
      digest: computeSaidDigest('RFI', vidSender, vidReceiver, { nonce: payload.nonce }),
    };
  } else if (payload.type === 'TSP_RFA') {
    resolvedPayload = {
      ...payload,
      replyDigest: computeSaidDigest('RFA', vidSender, vidReceiver, { requestDigest: payload.digest }),
    };
  }

  const payloadCesr = encodePayload(resolvedPayload);

  const signable = version + vidSndr + vidRcvr + payloadCesr;
  assertSignableWithinLimit(signable.length);
  const envelope = encodeEnvelopeTag(quadlets(signable)) + signable;

  // The signature authenticates the binary envelope (spec 9.5), including the
  // `-E##` frame and the exact encoded bytes.
  const sigPrim = signMessage(cesrTextToBinary(envelope), signingSecretKey);
  const sigGroup = Counter.v2.ControllerIdxSigs(quadlets(sigPrim)).text() + sigPrim;
  const attachment = Counter.v2.AttachmentGroup(quadlets(sigGroup)).text() + sigGroup;

  return utf8(envelope + attachment);
}

/** Extract the raw signature bytes from the attachment group. */
function extractSignature(sigPart: string): Uint8Array {
  const attach = peekCounter(sigPart); // -C##
  const inner = sigPart.slice(attach.n);
  const idxGroup = peekCounter(inner); // -K##
  const indexed = inner.slice(idxGroup.n);
  if (indexed.startsWith('1AAQ')) {
    return decodeMlDsa65Signature(indexed);
  }
  const idxPeek = Indexer.peek(utf8(indexed));
  if (!idxPeek.frame) {
    throw new SyntaxError('extractSignature: malformed indexed signature');
  }
  return new Uint8Array(idxPeek.frame.raw);
}

/** Open (decode and verify) a v3 TSP message. */
export function tspOpen(params: TspOpenParams): TspEnvelope {
  const { message, senderPublicKey } = params;
  const messageText = text(message);

  const env = peekCounter(messageText);
  if (!isCounterFamily(env.code, 'E')) {
    throw new SyntaxError(`tspOpen: expected -E signable-data envelope (small or Big form), got "${env.code}"`);
  }
  const signable = messageText.slice(env.n, env.n + env.count * 4);
  const envelope = messageText.slice(0, env.n + env.count * 4);
  const sigPart = messageText.slice(env.n + env.count * 4);

  const version = signable.slice(0, 8);
  const sndr = peekMatter(signable.slice(8));
  const vidSender = text(sndr.raw);
  const rcvr = peekMatter(signable.slice(8 + sndr.n));
  const vidReceiver = rcvr.raw.length === 0 ? null : text(rcvr.raw);
  const payloadCesr = signable.slice(8 + sndr.n + rcvr.n);

  const sigBytes = extractSignature(sigPart);
  if (!verifyMessage(sigBytes, cesrTextToBinary(envelope), senderPublicKey)) {
    throw new Error('tspOpen: signature verification failed');
  }

  const payload = decodePayload(payloadCesr, params.hpkeEncSize);
  return { version, vidSender, vidReceiver, payload };
}

// Re-export the nonce length used by relationship code.
export { NONCE_BYTES };

// ---------------------------------------------------------------------------
// Peek (parse without signature verification)
// ---------------------------------------------------------------------------

/** A structurally-parsed envelope (signature NOT verified). */
export interface PeekedEnvelope {
  version: string;
  vidSender: Vid;
  vidReceiver: Vid | null;
  payloadType: 'TSP_GEN' | 'TSP_RFI' | 'TSP_RFA' | 'TSP_RFD' | 'TSP_GEN_CONFIDENTIAL';
  /** Present for RFI/RFA when the sender inlined its DID document. */
  didDocument?: DidDocument;
  /**
   * Digest carried by the payload (the request digest for XRFI/XRFA, or the
   * declined digest for XRFD). Exposed so a receiver can CORRELATE an inbound
   * message with the relationship/ceremony it refers to — and log which invite a
   * decline answers — without needing the sender's key to verify it first.
   */
  digest?: Uint8Array;
}

/**
 * Parse a TSP message envelope WITHOUT verifying the signature. Used by the
 * relationship layer to resolve the sender VID (DID) to its verification key
 * before calling tspOpen().
 */
export function peekEnvelope(message: Uint8Array): PeekedEnvelope {
  const messageText = text(message);
  const env = peekCounter(messageText);
  if (!isCounterFamily(env.code, 'E')) {
    throw new SyntaxError(`peekEnvelope: expected -E signable-data envelope (small or Big form), got "${env.code}"`);
  }
  const signable = messageText.slice(env.n, env.n + env.count * 4);
  const version = signable.slice(0, 8);
  const sndr = peekMatter(signable.slice(8));
  const vidSender = text(sndr.raw);
  const rcvr = peekMatter(signable.slice(8 + sndr.n));
  const vidReceiver = rcvr.raw.length === 0 ? null : text(rcvr.raw);
  const payloadCesr = signable.slice(8 + sndr.n + rcvr.n);
  const payload = decodePayload(payloadCesr);
  const didDocument =
    payload.type === 'TSP_RFI' || payload.type === 'TSP_RFA'
      ? (payload as TspRfiPayload | TspRfaPayload).didDocument
      : undefined;
  const digest =
    payload.type === 'TSP_RFI' || payload.type === 'TSP_RFA' || payload.type === 'TSP_RFD'
      ? (payload as { digest?: Uint8Array }).digest
      : undefined;
  return { version, vidSender, vidReceiver, payloadType: payload.type, didDocument, digest };
}

