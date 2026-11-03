import { timingSafeEqual } from "node:crypto";
import { concatenate, decodeDomain, formatIPv4, formatIPv6, type Destination } from "./wire";

export const VL_VERSION = 0;
export const VL_COMMAND_TCP = 1;
export const MAX_HANDSHAKE_BYTES = 1024;
const VL_USER_ID_BYTES = 16;
const VL_USER_ID_OFFSET = 1;
const VL_ADDON_LENGTH_OFFSET = VL_USER_ID_OFFSET + VL_USER_ID_BYTES;

export interface VLRequest {
  version: 0;
  userId: Uint8Array;
  command: "tcp";
  destination: Destination;
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
  | "authentication_failed"
  | "parser_already_complete";

export class VlProtocolError extends Error {
  readonly code: VLProtocolErrorCode;

  constructor(code: VLProtocolErrorCode) {
    super("invalid VL request");
    this.name = "VlProtocolError";
    this.code = code;
  }
}

interface HeaderParseResult {
  request: VLRequest;
  headerLength: number;
}

function parseHeader(bytes: Uint8Array): HeaderParseResult | undefined {
  if (bytes.length < 1) return undefined;
  if (bytes[0] !== VL_VERSION) throw new VlProtocolError("unsupported_version");
  if (bytes.length < VL_ADDON_LENGTH_OFFSET + 1) return undefined;

  const userId = bytes.slice(VL_USER_ID_OFFSET, VL_ADDON_LENGTH_OFFSET);
  const addonLength = bytes[VL_ADDON_LENGTH_OFFSET]!;
  if (addonLength !== 0) throw new VlProtocolError("unsupported_addons");
  let offset = VL_ADDON_LENGTH_OFFSET + 1 + addonLength;
  if (bytes.length < offset + 4) return undefined;

  const command = bytes[offset]!;
  offset += 1;
  if (command !== VL_COMMAND_TCP) throw new VlProtocolError("unsupported_command");

  const port = (bytes[offset]! << 8) | bytes[offset + 1]!;
  offset += 2;
  if (port === 0) throw new VlProtocolError("invalid_port");

  const addressType = bytes[offset]!;
  offset += 1;
  let host: string;

  if (addressType === 1) {
    if (bytes.length < offset + 4) return undefined;
    host = formatIPv4(bytes.subarray(offset, offset + 4));
    offset += 4;
  } else if (addressType === 2) {
    if (bytes.length < offset + 1) return undefined;
    const domainLength = bytes[offset]!;
    offset += 1;
    if (domainLength === 0) throw new VlProtocolError("invalid_domain");
    if (bytes.length < offset + domainLength) return undefined;
    const domain = decodeDomain(bytes.subarray(offset, offset + domainLength));
    if (domain === undefined) throw new VlProtocolError("invalid_domain");
    host = domain;
    offset += domainLength;
  } else if (addressType === 3) {
    if (bytes.length < offset + 16) return undefined;
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
      destination: { host, port }
    },
    headerLength: offset
  };
}

export class VlHandshakeParser {
  readonly #maximumBytes: number;
  readonly #expectedUserId: Uint8Array | undefined;
  #buffer: Uint8Array = new Uint8Array();
  #complete = false;

  constructor(maximumBytes = MAX_HANDSHAKE_BYTES, expectedUserId?: Uint8Array) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 24) {
      throw new RangeError("maximum handshake size is invalid");
    }
    if (expectedUserId !== undefined && expectedUserId.byteLength !== VL_USER_ID_BYTES) {
      throw new RangeError("user ID is invalid");
    }
    this.#maximumBytes = maximumBytes;
    this.#expectedUserId = expectedUserId?.slice();
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

    if (this.#expectedUserId !== undefined && !authenticateVlUser(parsed.request.userId, this.#expectedUserId)) {
      throw new VlProtocolError("authentication_failed");
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

export function parseVlUUID(value: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error("UUID secret is invalid");
  }

  const hex = value.replaceAll("-", "");
  const userId = new Uint8Array(VL_USER_ID_BYTES);
  for (let index = 0; index < userId.length; index += 1) {
    userId[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return userId;
}

export function authenticateVlUser(provided: Uint8Array, expected: Uint8Array): boolean {
  return (
    provided.byteLength === VL_USER_ID_BYTES &&
    expected.byteLength === VL_USER_ID_BYTES &&
    timingSafeEqual(provided, expected)
  );
}
