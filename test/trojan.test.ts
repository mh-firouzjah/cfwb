import { describe, expect, it } from "vitest";
import { MAX_TR_PASSWORD_BYTES, TrHandshakeParser, TrProtocolError, sha224Hex } from "../src/protocol/tr";
import { trRequest } from "./trojan-fixtures";

const PASSWORD = "unit-test-tr-password";

function xorshift32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

describe("Trojan protocol", () => {
  it("matches the standard SHA-224 test vectors", () => {
    expect(sha224Hex(new Uint8Array())).toBe("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    expect(sha224Hex(new TextEncoder().encode("abc"))).toBe("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
  });

  it("hashes UTF-8 password bytes", () => {
    const nonAscii = sha224Hex(new TextEncoder().encode("pässword"));
    expect(nonAscii).toBe("67c1cc6da21aa0ad60de9d6f52645d715a01a1c4ef4e73ee0b14d8f7");
  });

  it("enforces the password limit in UTF-8 bytes", () => {
    expect(MAX_TR_PASSWORD_BYTES).toBe(512);
    expect(() => new TrHandshakeParser("x".repeat(MAX_TR_PASSWORD_BYTES))).not.toThrow();
    expect(() => new TrHandshakeParser("x".repeat(MAX_TR_PASSWORD_BYTES + 1))).toThrow(RangeError);
    expect(() => new TrHandshakeParser("é".repeat(257))).toThrow(RangeError);
  });

  it("parses a fragmented header and preserves initial TCP payload", () => {
    const payload = Uint8Array.of(0x16, 0x03, 0x01, 0x00, 0x09, 0x01, 0x02, 0x03);
    const bytes = trRequest(PASSWORD, { host: "www.example.com", payload });
    const parser = new TrHandshakeParser(PASSWORD);

    expect(parser.push(bytes.subarray(0, 13))).toBeUndefined();
    expect(parser.push(bytes.subarray(13, 57))).toBeUndefined();
    expect(parser.push(bytes.subarray(57, 64))).toBeUndefined();
    const parsed = parser.push(bytes.subarray(64));

    expect(parsed?.destination).toEqual({ host: "www.example.com", port: 443 });
    expect(parsed?.initialPayload).toEqual(payload);
  });

  it("parses IPv4 and IPv6 destinations", () => {
    const ipv4 = trRequest(PASSWORD, {
      addressType: 1,
      addressBytes: Uint8Array.of(93, 184, 216, 34),
      port: 8443
    });
    expect(new TrHandshakeParser(PASSWORD).push(ipv4)?.destination).toEqual({
      host: "93.184.216.34",
      port: 8443
    });

    const ipv6 = trRequest(PASSWORD, {
      addressType: 4,
      addressBytes: Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    });
    expect(new TrHandshakeParser(PASSWORD).push(ipv6)?.destination).toEqual({
      host: "2001:db8::1",
      port: 443
    });
  });

  it("rejects a non-hexadecimal digest prefix immediately", () => {
    const parser = new TrHandshakeParser(PASSWORD);
    expect(() => parser.push(Uint8Array.of(0x00))).toThrowError(expect.objectContaining({ code: "invalid_header" }));
  });

  it("rejects a password mismatch", () => {
    expect(() => new TrHandshakeParser(PASSWORD).push(trRequest("incorrect-password"))).toThrowError(
      expect.objectContaining({ code: "authentication_failed" })
    );
  });

  it("rejects UDP because the Worker supports TCP only", () => {
    expect(() => new TrHandshakeParser(PASSWORD).push(trRequest(PASSWORD, { command: 3 }))).toThrowError(
      expect.objectContaining({ code: "unsupported_command" })
    );
  });

  it("rejects malformed CRLF and zero destination ports", () => {
    const malformedLine = trRequest(PASSWORD);
    malformedLine[malformedLine.length - 1] = 0;
    expect(() => new TrHandshakeParser(PASSWORD).push(malformedLine)).toThrowError(
      expect.objectContaining({ code: "invalid_header" })
    );

    expect(() => new TrHandshakeParser(PASSWORD).push(trRequest(PASSWORD, { port: 0 }))).toThrowError(
      expect.objectContaining({ code: "invalid_port" })
    );
  });

  it("bounds incomplete headers and forbids parser reuse after completion", () => {
    const request = trRequest(PASSWORD, { host: "example.com" });
    expect(() => new TrHandshakeParser(PASSWORD, 64).push(request.subarray(0, 64))).toThrowError(
      expect.objectContaining({ code: "handshake_too_large" })
    );

    const parser = new TrHandshakeParser(PASSWORD);
    parser.push(request);
    expect(() => parser.push(new Uint8Array())).toThrowError(
      expect.objectContaining({ code: "parser_already_complete" })
    );
  });

  it("accepts every split point in a valid handshake", () => {
    const payload = Uint8Array.of(1, 2, 3);
    const bytes = trRequest(PASSWORD, { host: "example.com", payload });
    const headerLength = bytes.byteLength - payload.byteLength;

    for (let split = 1; split < headerLength; split += 1) {
      const parser = new TrHandshakeParser(PASSWORD);
      expect(parser.push(bytes.subarray(0, split))).toBeUndefined();
      const parsed = parser.push(bytes.subarray(split));
      expect(parsed?.initialPayload).toEqual(payload);
      expect(parsed?.destination).toEqual({ host: "example.com", port: 443 });
    }
  });

  it("rejects malformed address types and domain fields", () => {
    const invalidType = trRequest(PASSWORD);
    invalidType[59] = 9;
    expect(() => new TrHandshakeParser(PASSWORD).push(invalidType)).toThrowError(
      expect.objectContaining({ code: "invalid_address_type" })
    );

    const emptyDomain = trRequest(PASSWORD);
    emptyDomain[60] = 0;
    expect(() => new TrHandshakeParser(PASSWORD).push(emptyDomain)).toThrowError(
      expect.objectContaining({ code: "invalid_domain" })
    );

    const invalidDomain = trRequest(PASSWORD);
    invalidDomain[61] = 0x40;
    expect(() => new TrHandshakeParser(PASSWORD).push(invalidDomain)).toThrowError(
      expect.objectContaining({ code: "invalid_domain" })
    );
  });

  it("keeps deterministic mutations of authenticated handshakes inside the protocol error boundary", () => {
    const random = xorshift32(0x51a7e);
    const valid = trRequest(PASSWORD, { host: "example.com", payload: Uint8Array.of(1, 2, 3, 4) });

    for (let caseIndex = 0; caseIndex < 1_000; caseIndex += 1) {
      const bytes = valid.slice();
      const mutations = 1 + (random() % 4);
      for (let mutation = 0; mutation < mutations; mutation += 1) {
        // Keep the SHA-224 digest valid so mutations reach header/address parsing.
        const offset = 56 + (random() % (bytes.byteLength - 56));
        bytes[offset] = bytes[offset]! ^ (random() & 0xff || 1);
      }

      const parser = new TrHandshakeParser(PASSWORD);
      let offset = 0;
      try {
        while (offset < bytes.byteLength) {
          const fragmentLength = 1 + (random() % 53);
          const parsed = parser.push(bytes.subarray(offset, offset + fragmentLength));
          offset += fragmentLength;
          if (parsed !== undefined) {
            expect(parsed.destination.port).toBeGreaterThan(0);
            expect(parsed.destination.port).toBeLessThanOrEqual(65_535);
            expect(parsed.destination.host.length).toBeGreaterThan(0);
            expect(parsed.initialPayload).toBeInstanceOf(Uint8Array);
            break;
          }
        }
      } catch (error) {
        expect(error).toBeInstanceOf(TrProtocolError);
      }
    }
  });
});
