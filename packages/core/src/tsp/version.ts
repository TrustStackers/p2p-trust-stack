/**
 * TSP version string codec — Rev 3.
 *
 * Wire form: `YTSP-###` (8 chars). `YTSP-` is the TSP version code (a CESR
 * version-string tag); `###` encodes MAJOR (first char, base64url) and MINOR
 * (next two chars, base64url: MINOR = 64 * c1 + c2, range 0–4095).
 *
 * The current experimental draft version is `YTSP-AAC` = 0.2 (major 0, minor 2).
 * MAJOR signals that backward compatibility MAY not be maintained with previous
 * versions; MINOR increments within a compatible MAJOR line.
 */

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const B64_VALUE: Record<string, number> = (() => {
  const map: Record<string, number> = {};
  for (let i = 0; i < B64_ALPHABET.length; i++) map[B64_ALPHABET[i]] = i;
  return map;
})();

/** The TSP version-string code prefix (CESR `Y` Tag7 with protocol "TSP-"). */
export const TSP_VERSION_CODE = 'YTSP-' as const;

/** The Rev 3 experimental draft version string (major 0, minor 2). */
export const TSP_VERSION_0_2 = 'YTSP-AAC' as const;

export interface TspVersion {
  /** 0–63. A change here MAY break backward compatibility. */
  major: number;
  /** 0–4095. */
  minor: number;
}

/** The TSP version this build speaks (Rev 3, experimental draft 0.2). */
export const TSP_CURRENT_VERSION: TspVersion = { major: 0, minor: 2 };

/** The TSP version string this build emits. */
export const TSP_CURRENT_VERSION_STRING: string = encodeTspVersion(
  TSP_CURRENT_VERSION.major,
  TSP_CURRENT_VERSION.minor,
);

/**
 * Encode a MAJOR.MINOR pair as an 8-character `YTSP-###` version string.
 * @throws RangeError if major ∉ [0,63] or minor ∉ [0,4095]
 */
export function encodeTspVersion(major: number, minor: number): string {
  if (!Number.isInteger(major) || major < 0 || major > 63) {
    throw new RangeError(`encodeTspVersion: major must be an integer 0–63, got ${major}`);
  }
  if (!Number.isInteger(minor) || minor < 0 || minor > 4095) {
    throw new RangeError(`encodeTspVersion: minor must be an integer 0–4095, got ${minor}`);
  }
  const c1 = Math.floor(minor / 64);
  const c2 = minor % 64;
  return `${TSP_VERSION_CODE}${B64_ALPHABET[major]}${B64_ALPHABET[c1]}${B64_ALPHABET[c2]}`;
}

/**
 * Decode an 8-character `YTSP-###` version string to its MAJOR.MINOR pair.
 * @throws SyntaxError if the string is not a well-formed TSP version string
 */
export function decodeTspVersion(version: string): TspVersion {
  if (version.length !== 8 || !version.startsWith(TSP_VERSION_CODE)) {
    throw new SyntaxError(
      `decodeTspVersion: expected 8-char "${TSP_VERSION_CODE}###" string, got ${JSON.stringify(version)}`,
    );
  }
  const a = B64_VALUE[version[5]];
  const b = B64_VALUE[version[6]];
  const c = B64_VALUE[version[7]];
  if (a === undefined || b === undefined || c === undefined) {
    throw new SyntaxError(`decodeTspVersion: invalid base64url chars in ${JSON.stringify(version)}`);
  }
  return { major: a, minor: b * 64 + c };
}
