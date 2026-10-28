import { describe, expect, it } from "vitest";
import {
  buildVlResponseHeader,
  MAX_HANDSHAKE_BYTES,
  VlHandshakeParser,
  VlProtocolError,
  type VLProtocolErrorCode
} from "../src/protocol/vl";
import { requestBytes, VALID_UUID_BYTES } from "./fixtures";

function parse(bytes: Uint8Array) {
  const parsed = new VlHandshakeParser().push(bytes);
  expect(parsed).toBeDefined();
  return parsed!;
}

function expectCode(bytes: Uint8Array, code: VLProtocolErrorCode): void {
  try {
    new VlHandshakeParser().push(bytes);
    throw new Error("expected parser failure");
  } catch (error) {
    if (!(error instanceof VlProtocolError)) throw error;
    expect(error.code).toBe(code);
  }
}

describe("VL version-0 streaming parser", () => {
  it("parses a domain destination and coalesced payload", () => {
    const payload = Uint8Array.from([0x16, 0x03, 0x01]);
    const result = parse(requestBytes({ payload }));
    expect(result.request).toMatchObject({
      version: 0,
      command: "tcp",
      destination: { type: "domain", host: "example", port: 443 }
    });
    expect(result.request.userId).toEqual(VALID_UUID_BYTES);
    expect(result.initialPayload).toEqual(payload);
  });

  it("supports IPv4", () => {
    const result = parse(
      requestBytes({
        addressType: 1,
        address: Uint8Array.from([203, 0, 113, 7])
      })
    );
    expect(result.request.destination).toEqual({ type: "ipv4", host: "203.0.113.7", port: 443 });
  });

  it("supports IPv6", () => {
    const result = parse(
      requestBytes({
        addressType: 3,
        address: Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
      })
    );
    expect(result.request.destination).toEqual({ type: "ipv6", host: "2001:db8::1", port: 443 });
  });

  it("waits for a fragmented first frame", () => {
    const bytes = requestBytes();
    const parser = new VlHandshakeParser();
    expect(parser.push(bytes.subarray(0, 1))).toBeUndefined();
    expect(parser.push(bytes.subarray(1, 17))).toBeUndefined();
    expect(parser.push(bytes.subarray(17))).toBeDefined();
  });

  it("accepts every possible split point", () => {
    const bytes = requestBytes({ payload: Uint8Array.from([1, 2, 3]) });
    const headerLength = bytes.length - 3;
    for (let split = 1; split < headerLength; split += 1) {
      const parser = new VlHandshakeParser();
      expect(parser.push(bytes.subarray(0, split))).toBeUndefined();
      const parsed = parser.push(bytes.subarray(split));
      expect(parsed?.initialPayload).toEqual(Uint8Array.from([1, 2, 3]));
    }
  });

  it("rejects nonzero protocol add-on lengths in the fixed subset", () => {
    expectCode(requestBytes({ addons: Uint8Array.from([0xaa, 0xbb]) }), "unsupported_addons");
  });

  it("rejects domain bytes outside Xray's wire character set", () => {
    expectCode(requestBytes({ address: Uint8Array.from([3, 0x61, 0x40, 0x62]) }), "invalid_domain");
  });

  it("rejects unsupported versions", () => expectCode(requestBytes({ version: 1 }), "unsupported_version"));
  it("rejects UDP", () => expectCode(requestBytes({ command: 2 }), "unsupported_command"));
  it("rejects Mux", () => expectCode(requestBytes({ command: 3 }), "unsupported_command"));
  it("rejects malformed address types", () => expectCode(requestBytes({ addressType: 9 }), "invalid_address_type"));
  it("rejects zero ports", () => expectCode(requestBytes({ port: 0 }), "invalid_port"));
  it("rejects zero-length domains", () => expectCode(requestBytes({ address: Uint8Array.of(0) }), "invalid_domain"));

  it("continues waiting for truncated addresses", () => {
    const bytes = requestBytes({ addressType: 1, address: Uint8Array.from([192, 0]) });
    expect(new VlHandshakeParser().push(bytes)).toBeUndefined();
  });

  it("rejects a handshake that cannot complete within the bound", () => {
    const bytes = Uint8Array.from([
      0,
      ...VALID_UUID_BYTES,
      0,
      1,
      1,
      187,
      2,
      255,
      ...new Uint8Array(MAX_HANDSHAKE_BYTES)
    ]);
    try {
      new VlHandshakeParser(64).push(bytes);
      throw new Error("expected parser failure");
    } catch (error) {
      if (!(error instanceof VlProtocolError)) throw error;
      expect(error.code).toBe("handshake_too_large");
    }
  });

  it("generates the response header exactly", () => {
    expect(buildVlResponseHeader()).toEqual(Uint8Array.of(0, 0));
  });
});
