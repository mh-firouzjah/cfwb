export const VL_VERSION = 0;
export const VL_COMMAND_TCP = 1;
export const MAX_HANDSHAKE_BYTES = 1024;

export type VlAddressType = "ipv4" | "domain" | "ipv6";

export interface VlDestination {
  type: VlAddressType;
  host: string;
  port: number;
}

export interface VLRequest {
  version: 0;
  userId: Uint8Array;
  command: "tcp";
  destination: VlDestination;
}

export interface ParsedVlHandshake {
  request: VLRequest;
  initialPayload: Uint8Array;
}

export type VLProtocolErrorCode =
  | "unsupported_version"
  | "unsupported_addons"
  | "unsupported_command"
  | "invalid_address_type"
  | "invalid_domain"
  | "invalid_port"
  | "handshake_too_large"
  | "parser_already_complete";

export class VlProtocolError extends Error {
  readonly code: VLProtocolErrorCode;

  constructor(code: VLProtocolErrorCode) {
    super("invalid VL request");
    this.name = "VLProtocolError";
    this.code = code;
  }
}

interface HeaderParseResult {
  request: VLRequest;
  headerLength: number;
}

function concatenate(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length === 0) return right.slice();
  if (right.length === 0) return left.slice();
  const result = new Uint8Array(left.length + right.length);
  result.set(left, 0);
  result.set(right, left.length);
  return result;
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

function decodeDomain(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    const character = String.fromCharCode(byte);
    if (!/[A-Za-z0-9._-]/.test(character)) throw new VlProtocolError("invalid_domain");
    result += character;
  }
  return result;
}

function parseHeader(bytes: Uint8Array): HeaderParseResult | undefined {
  if (bytes.length < 1) return undefined;
  if (bytes[0] !== VL_VERSION) throw new VlProtocolError("unsupported_version");
  if (bytes.length < 18) return undefined;

  const userId = bytes.slice(1, 17);
  const addonLength = bytes[17]!;
  if (addonLength !== 0) throw new VlProtocolError("unsupported_addons");
  let offset = 18 + addonLength;
  if (bytes.length < offset + 4) return undefined;

  const command = bytes[offset]!;
  offset += 1;
  if (command !== VL_COMMAND_TCP) throw new VlProtocolError("unsupported_command");

  const port = (bytes[offset]! << 8) | bytes[offset + 1]!;
  offset += 2;
  if (port === 0) throw new VlProtocolError("invalid_port");

  const addressType = bytes[offset]!;
  offset += 1;
  let type: VlAddressType;
  let host: string;

  if (addressType === 1) {
    if (bytes.length < offset + 4) return undefined;
    type = "ipv4";
    host = Array.from(bytes.subarray(offset, offset + 4)).join(".");
    offset += 4;
  } else if (addressType === 2) {
    if (bytes.length < offset + 1) return undefined;
    const domainLength = bytes[offset]!;
    offset += 1;
    if (domainLength === 0) throw new VlProtocolError("invalid_domain");
    if (bytes.length < offset + domainLength) return undefined;
    type = "domain";
    host = decodeDomain(bytes.subarray(offset, offset + domainLength));
    offset += domainLength;
  } else if (addressType === 3) {
    if (bytes.length < offset + 16) return undefined;
    type = "ipv6";
    host = formatIPv6(bytes.subarray(offset, offset + 16));
    offset += 16;
  } else {
    throw new VlProtocolError("invalid_address_type");
  }

  return {
    request: {
      version: VL_VERSION,
      userId,
      command: "tcp",
      destination: { type, host, port }
    },
    headerLength: offset
  };
}

export class VlHandshakeParser {
  readonly #maximumBytes: number;
  #buffer: Uint8Array = new Uint8Array();
  #complete = false;

  constructor(maximumBytes = MAX_HANDSHAKE_BYTES) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 24) {
      throw new RangeError("maximum handshake size is invalid");
    }
    this.#maximumBytes = maximumBytes;
  }

  push(chunk: Uint8Array): ParsedVlHandshake | undefined {
    if (this.#complete) throw new VlProtocolError("parser_already_complete");

    const prior = this.#buffer;
    const remaining = this.#maximumBytes - prior.length;
    const prefixLength = Math.min(chunk.length, Math.max(remaining, 0));
    const candidate = concatenate(prior, chunk.subarray(0, prefixLength));
    const parsed = parseHeader(candidate);

    if (parsed === undefined) {
      if (prefixLength < chunk.length || candidate.length >= this.#maximumBytes) {
        throw new VlProtocolError("handshake_too_large");
      }
      this.#buffer = candidate;
      return undefined;
    }

    this.#complete = true;
    let initialPayload: Uint8Array;
    if (parsed.headerLength < prior.length) {
      initialPayload = concatenate(prior.subarray(parsed.headerLength), chunk);
    } else {
      initialPayload = chunk.slice(parsed.headerLength - prior.length);
    }
    this.#buffer = new Uint8Array();
    return { request: parsed.request, initialPayload };
  }
}

export function buildVlResponseHeader(): Uint8Array {
  return Uint8Array.of(VL_VERSION, 0);
}
