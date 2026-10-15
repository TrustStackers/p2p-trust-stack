// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Name URI parser, validator, and serializer for agent names.
 *
 * Format: vta:<namespace>:<name>
 *
 * Examples:
 *   vta:p2pts.mainnet:alice
 *   vta:example.com:validator-7
 *
 * Namespaces are hierarchical (dot-separated) to support federation.
 * Names are case-sensitive and may contain alphanumerics, hyphens, and underscores.
 */

const NAME_URI_REGEX = /^vta:([a-zA-Z0-9][a-zA-Z0-9.-]*):([a-zA-Z0-9][a-zA-Z0-9_-]{0,63})$/;

export interface NameUri {
  /** The full URI string, e.g. "vta:p2pts.mainnet:alice". */
  uri: string;
  /** The namespace portion, e.g. "p2pts.mainnet". */
  namespace: string;
  /** The name portion, e.g. "alice". */
  name: string;
}

/** Parse a vta:<namespace>:<name> URI string. Throws on invalid format. */
export function parseNameUri(uri: string): NameUri {
  const match = uri.match(NAME_URI_REGEX);
  if (!match) {
    throw new Error(
      `Invalid agent name URI "${uri}": expected format vta:<namespace>:<name>. ` +
      `Namespace must be dot-separated alphanumeric segments. Name must be 1-64 chars (alphanumeric, -, _).`,
    );
  }
  return {
    uri,
    namespace: match[1],
    name: match[2],
  };
}

/** Build a name URI from namespace and name parts. */
export function buildNameUri(namespace: string, name: string): string {
  const uri = `vta:${namespace}:${name}`;
  // Validate by parsing — ensures both parts are well-formed
  parseNameUri(uri);
  return uri;
}

/** Check if a string is a valid vta name URI without constructing the object. */
export function isValidNameUri(uri: string): boolean {
  return NAME_URI_REGEX.test(uri);
}