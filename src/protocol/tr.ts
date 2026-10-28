import { createHash } from "node:crypto";

import type { VlDestination } from "./vl";

export function sha224Hex(message: Uint8Array): string {
  return createHash("sha224").update(message).digest("hex");
}

export const MAX_TR_HANDSHAKE_BYTES = 1024;
const PASSWORD_HASH_BYTES = 56;
const CRLF = 0x0d;
const LF = 0x0a;
const TR_COMMAND_TCP = 0x01;
const TR_COMMAND_UDP = 0x03;

export type TrProtocolErrorCode =
  | "authentication_failed"
  | "invalid_header"
  | "unsupported_command"
  | "invalid_address_type"
  | "invalid_domain"
  | "invalid_port"
  | "handshake_too_large"
  | "parser_already_complete";

export class TrProtocolError extends Error {
  readonly code: TrProtocolErrorCode;

  constructor(code: TrProtocolErrorCode) {
    super("invalid Tr request");
    this.name = "TrProtocolError";
    this.code = code;
  }
}

export interface ParsedTrHandshake {
  readonly destination: VlDestination;
  readonly initialPayload: Uint8Array;
}

interface HeaderParseResult {
  readonly destination: VlDestination;
  readonly headerLength: number;
}

function concatenate(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength === 0) return right.slice();
  if (right.byteLength === 0) return left.slice();
  const result = new Uint8Array(left.byteLength + right.byteLength);
  result.set(left);
  result.set(right, left.byteLength);
  return result;
}

function constantTimeHashMatch(received: Uint8Array, expected: Uint8Array): boolean {
  let difference = received.byteLength ^ expected.byteLength;
  for (let index = 0; index < PASSWORD_HASH_BYTES; index += 1) {
    difference |= (received[index] ?? 0) ^ (expected[index] ?? 0);
  }
  return difference === 0;
}

function decodeDomain(bytes: Uint8Array): string {
  if (bytes.byteLength === 0 || bytes.byteLength > 253) throw new TrProtocolError("invalid_domain");
  let domain = "";
  for (const byte of bytes) {
    const valid =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x2e;
    if (!valid) throw new TrProtocolError("invalid_domain");
    domain += String.fromCharCode(byte);
  }
  if (domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) {
    throw new TrProtocolError("invalid_domain");
  }
  return domain;
}

function formatIPv6(bytes: Uint8Array): string {
  const words: number[] = [];
  for (let offset = 0; offset < 16; offset += 2) {
    words.push((bytes[offset]! << 8) | bytes[offset + 1]!);
  }

  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < words.length;) {
    if (words[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < words.length && words[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  if (bestLength < 2) return words.map((word) => word.toString(16)).join(":");
  const left = words
    .slice(0, bestStart)
    .map((word) => word.toString(16))
    .join(":");
  const right = words
    .slice(bestStart + bestLength)
    .map((word) => word.toString(16))
    .join(":");
  if (left.length === 0 && right.length === 0) return "::";
  if (left.length === 0) return `::${right}`;
  if (right.length === 0) return `${left}::`;
  return `${left}::${right}`;
}

function parseHeader(bytes: Uint8Array, expectedPasswordHash: Uint8Array): HeaderParseResult | undefined {
  if (bytes.byteLength < PASSWORD_HASH_BYTES + 2) return undefined;

  if (!constantTimeHashMatch(bytes.subarray(0, PASSWORD_HASH_BYTES), expectedPasswordHash)) {
    throw new TrProtocolError("authentication_failed");
  }
  if (bytes[PASSWORD_HASH_BYTES] !== CRLF || bytes[PASSWORD_HASH_BYTES + 1] !== LF) {
    throw new TrProtocolError("invalid_header");
  }
  if (bytes.byteLength < 60) return undefined;

  const command = bytes[58]!;
  if (command !== TR_COMMAND_TCP) {
    if (command === TR_COMMAND_UDP) throw new TrProtocolError("unsupported_command");
    throw new TrProtocolError("unsupported_command");
  }

  const addressType = bytes[59]!;
  let addressLength: number;
  let addressOffset: number;
  let type: VlDestination["type"];
  let host: string;

  if (addressType === 0x01) {
    addressLength = 4;
    addressOffset = 60;
    if (bytes.byteLength < addressOffset + addressLength) return undefined;
    type = "ipv4";
    host = Array.from(bytes.subarray(addressOffset, addressOffset + addressLength)).join(".");
  } else if (addressType === 0x03) {
    if (bytes.byteLength < 61) return undefined;
    addressLength = bytes[60]!;
    addressOffset = 61;
    if (addressLength === 0 || addressLength > 253) throw new TrProtocolError("invalid_domain");
    if (bytes.byteLength < addressOffset + addressLength) return undefined;
    type = "domain";
    host = decodeDomain(bytes.subarray(addressOffset, addressOffset + addressLength));
  } else if (addressType === 0x04) {
    addressLength = 16;
    addressOffset = 60;
    if (bytes.byteLength < addressOffset + addressLength) return undefined;
    type = "ipv6";
    host = formatIPv6(bytes.subarray(addressOffset, addressOffset + addressLength));
  } else {
    throw new TrProtocolError("invalid_address_type");
  }

  const portOffset = addressOffset + addressLength;
  const headerLength = portOffset + 4;
  if (bytes.byteLength < headerLength) return undefined;
  const port = (bytes[portOffset]! << 8) | bytes[portOffset + 1]!;
  if (port === 0) throw new TrProtocolError("invalid_port");
  if (bytes[portOffset + 2] !== CRLF || bytes[portOffset + 3] !== LF) {
    throw new TrProtocolError("invalid_header");
  }

  return { destination: { type, host, port }, headerLength };
}

/**
 * Incremental Tr request parser. It authenticates the 56-byte SHA-224
 * password digest and accepts a header split across multiple WebSocket messages.
 * Any bytes after the terminating CRLF are preserved as initial TCP payload.
 */
export class TrHandshakeParser {
  readonly #maximumBytes: number;
  readonly #expectedPasswordHash: Uint8Array;
  #buffer: Uint8Array = new Uint8Array();
  #complete = false;

  constructor(password: string, maximumBytes = MAX_TR_HANDSHAKE_BYTES) {
    const passwordBytes = new TextEncoder().encode(password);
    if (passwordBytes.byteLength === 0 || passwordBytes.byteLength > 512) {
      throw new RangeError("Tr password length is invalid");
    }
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 64) {
      throw new RangeError("maximum Tr handshake size is invalid");
    }
    this.#maximumBytes = maximumBytes;
    this.#expectedPasswordHash = new TextEncoder().encode(sha224Hex(passwordBytes));
  }

  push(chunk: Uint8Array): ParsedTrHandshake | undefined {
    if (this.#complete) throw new TrProtocolError("parser_already_complete");

    const remainingCapacity = this.#maximumBytes - this.#buffer.byteLength;
    const prefixLength = Math.min(chunk.byteLength, Math.max(remainingCapacity, 0));
    const candidate = concatenate(this.#buffer, chunk.subarray(0, prefixLength));
    const parsed = parseHeader(candidate, this.#expectedPasswordHash);

    if (parsed === undefined) {
      if (prefixLength < chunk.byteLength || candidate.byteLength >= this.#maximumBytes) {
        throw new TrProtocolError("handshake_too_large");
      }
      this.#buffer = candidate;
      return undefined;
    }

    this.#complete = true;
    const payloadFromCandidate = candidate.subarray(parsed.headerLength);
    const payloadFromChunk = chunk.subarray(prefixLength);
    const initialPayload = concatenate(payloadFromCandidate, payloadFromChunk);
    this.#buffer = new Uint8Array();
    return { destination: parsed.destination, initialPayload };
  }
}
