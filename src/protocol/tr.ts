import { createHash, timingSafeEqual } from "node:crypto";

import { concatenate, decodeDomain, formatIPv4, formatIPv6, type Destination } from "./wire";

export function sha224Hex(message: Uint8Array): string {
  return createHash("sha224").update(message).digest("hex");
}

export const MAX_TR_HANDSHAKE_BYTES = 1024;
export const MAX_TR_PASSWORD_BYTES = 512;
const PASSWORD_HASH_BYTES = 56;
const CRLF = 0x0d;
const LF = 0x0a;
const TR_COMMAND_TCP = 0x01;

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
  readonly destination: Destination;
  readonly initialPayload: Uint8Array;
}

interface HeaderParseResult {
  readonly destination: Destination;
  readonly headerLength: number;
}

function parseHeader(bytes: Uint8Array, expectedPasswordHash: Uint8Array): HeaderParseResult | undefined {
  const digestPrefixLength = Math.min(bytes.byteLength, PASSWORD_HASH_BYTES);
  for (let index = 0; index < digestPrefixLength; index += 1) {
    const byte = bytes[index]!;
    const isLowerHex = (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66);
    if (!isLowerHex) throw new TrProtocolError("invalid_header");
  }

  if (bytes.byteLength < PASSWORD_HASH_BYTES + 2) return undefined;

  if (!timingSafeEqual(bytes.subarray(0, PASSWORD_HASH_BYTES), expectedPasswordHash)) {
    throw new TrProtocolError("authentication_failed");
  }
  if (bytes[PASSWORD_HASH_BYTES] !== CRLF || bytes[PASSWORD_HASH_BYTES + 1] !== LF) {
    throw new TrProtocolError("invalid_header");
  }
  if (bytes.byteLength < 60) return undefined;

  const command = bytes[58]!;
  if (command !== TR_COMMAND_TCP) throw new TrProtocolError("unsupported_command");

  const addressType = bytes[59]!;
  let addressLength: number;
  let addressOffset: number;
  let host: string;

  if (addressType === 0x01) {
    addressLength = 4;
    addressOffset = 60;
    if (bytes.byteLength < addressOffset + addressLength) return undefined;
    host = formatIPv4(bytes.subarray(addressOffset, addressOffset + addressLength));
  } else if (addressType === 0x03) {
    if (bytes.byteLength < 61) return undefined;
    addressLength = bytes[60]!;
    addressOffset = 61;
    if (addressLength === 0) throw new TrProtocolError("invalid_domain");
    if (bytes.byteLength < addressOffset + addressLength) return undefined;
    const domain = decodeDomain(bytes.subarray(addressOffset, addressOffset + addressLength));
    if (domain === undefined) throw new TrProtocolError("invalid_domain");
    host = domain;
  } else if (addressType === 0x04) {
    addressLength = 16;
    addressOffset = 60;
    if (bytes.byteLength < addressOffset + addressLength) return undefined;
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

  return { destination: { host, port }, headerLength };
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
    if (passwordBytes.byteLength === 0 || passwordBytes.byteLength > MAX_TR_PASSWORD_BYTES) {
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
