import { timingSafeEqual } from "node:crypto";

export interface Credential {
  readonly uuid: Uint8Array;
  readonly path: string;
}

export function uuidStringToBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error("UUID secret is invalid");
  }
  const hex = value.replaceAll("-", "");
  const bytes = new Uint8Array(16);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function parseWebSocketPath(value: string): string {
  if (!/^\/[A-Za-z0-9_-]{16,128}$/.test(value)) {
    throw new Error("WebSocket path secret is invalid");
  }
  return value;
}

export function parseCredential(uuid: string, path: string): Credential {
  return { uuid: uuidStringToBytes(uuid), path: parseWebSocketPath(path) };
}

export function authenticateUser(provided: Uint8Array, expected: Uint8Array): boolean {
  const normalizedProvided = new Uint8Array(16);
  normalizedProvided.set(provided.subarray(0, normalizedProvided.length));
  const normalizedExpected = new Uint8Array(16);
  normalizedExpected.set(expected.subarray(0, normalizedExpected.length));
  const bytesMatch = timingSafeEqual(normalizedProvided, normalizedExpected);
  return bytesMatch && provided.length === 16 && expected.length === 16;
}
