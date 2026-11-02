export type { Destination } from "../contracts";

export function concatenate(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength === 0) return right.slice();
  if (right.byteLength === 0) return left.slice();
  const result = new Uint8Array(left.byteLength + right.byteLength);
  result.set(left);
  result.set(right, left.byteLength);
  return result;
}

/**
 * Decodes a wire domain name. Only [A-Za-z0-9._-] is accepted so the value is
 * always a plain hostname; length and DNS validity are the runtime's concern.
 */
export function decodeDomain(bytes: Uint8Array): string | undefined {
  if (bytes.byteLength === 0) return undefined;
  let domain = "";
  for (const byte of bytes) {
    const valid =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x2e ||
      byte === 0x5f;
    if (!valid) return undefined;
    domain += String.fromCharCode(byte);
  }
  return domain;
}

export function formatIPv4(bytes: Uint8Array): string {
  if (bytes.byteLength !== 4) throw new RangeError("IPv4 address must contain 4 bytes");
  return Array.from(bytes).join(".");
}

const hex = (group: number): string => group.toString(16);

/** Formats exactly 16 bytes as an RFC 5952 IPv6 literal. */
export function formatIPv6(bytes: Uint8Array): string {
  if (bytes.byteLength !== 16) throw new RangeError("IPv6 address must contain 16 bytes");
  const groups: number[] = [];
  for (let index = 0; index < 16; index += 2) groups.push((bytes[index]! << 8) | bytes[index + 1]!);

  // Longest run of zero groups (first on ties); a single zero group is not compressed.
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < 8;) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < 8 && groups[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  if (bestLength < 2) return groups.map(hex).join(":");
  const head = groups.slice(0, bestStart).map(hex).join(":");
  const tail = groups
    .slice(bestStart + bestLength)
    .map(hex)
    .join(":");
  return `${head}::${tail}`;
}
