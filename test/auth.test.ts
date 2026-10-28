import { describe, expect, it } from "vitest";
import { authenticateUser, parseCredential, parseWebSocketPath, uuidStringToBytes } from "../src/auth";
import { VALID_UUID, VALID_UUID_BYTES } from "./fixtures";

describe("separate UUID and WebSocket path credentials", () => {
  it("parses canonical UUID bytes", () => {
    expect(uuidStringToBytes(VALID_UUID)).toEqual(VALID_UUID_BYTES);
  });

  it("parses both secrets independently", () => {
    expect(parseCredential(VALID_UUID, "/this-is-a-valid-test-path")).toEqual({
      uuid: VALID_UUID_BYTES,
      path: "/this-is-a-valid-test-path"
    });
  });

  it("rejects malformed UUID and path secrets", () => {
    expect(() => uuidStringToBytes("not-a-uuid")).toThrow("UUID secret is invalid");
    expect(() => parseWebSocketPath("short")).toThrow("WebSocket path secret is invalid");
    expect(() => parseWebSocketPath("/path/with/slashes-123456")).toThrow("WebSocket path secret is invalid");
  });

  it("authenticates the current UUID", () => {
    expect(authenticateUser(VALID_UUID_BYTES, uuidStringToBytes(VALID_UUID))).toBe(true);
  });

  it("rejects an invalid UUID", () => {
    const invalid = VALID_UUID_BYTES.slice();
    invalid[15] = invalid[15]! ^ 1;
    expect(authenticateUser(invalid, uuidStringToBytes(VALID_UUID))).toBe(false);
  });

  it("requires both credentials to be valid at parse time", () => {
    expect(() => parseCredential(VALID_UUID, "/invalid")).toThrow("WebSocket path secret is invalid");
  });
});
