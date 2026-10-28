import { describe, expect, it } from "vitest";
import { TrHandshakeParser, TrProtocolError, sha224Hex } from "../src/protocol/tr";
import { trRequest } from "./trojan-fixtures";

const PASSWORD = "unit-test-tr-password";

describe("SHA-224 password digest", () => {
  it("matches the standard empty-message vector", () => {
    expect(sha224Hex(new Uint8Array())).toBe("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
  });

  it("matches the standard abc vector", () => {
    expect(sha224Hex(new TextEncoder().encode("abc"))).toBe("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
  });

  it("hashes UTF-8 bytes rather than rejecting non-ASCII passwords", () => {
    expect(sha224Hex(new TextEncoder().encode("pässword"))).toMatch(/^[0-9a-f]{56}$/);
    expect(sha224Hex(new TextEncoder().encode("pässword"))).not.toBe(sha224Hex(new TextEncoder().encode("password")));
  });
});

describe("incremental Tr handshake parser", () => {
  it("parses a fragmented header and preserves the initial TCP payload", () => {
    const payload = Uint8Array.of(0x16, 0x03, 0x01, 0x00, 0x09, 0x01, 0x02, 0x03);
    const bytes = trRequest(PASSWORD, { host: "www.example.com", payload });
    const parser = new TrHandshakeParser(PASSWORD);

    expect(parser.push(bytes.subarray(0, 13))).toBeUndefined();
    expect(parser.push(bytes.subarray(13, 57))).toBeUndefined();
    expect(parser.push(bytes.subarray(57, 64))).toBeUndefined();
    const parsed = parser.push(bytes.subarray(64));

    expect(parsed?.destination).toEqual({ type: "domain", host: "www.example.com", port: 443 });
    expect(parsed?.initialPayload).toEqual(payload);
  });

  it("parses IPv4 destinations and non-default ports", () => {
    const bytes = trRequest(PASSWORD, {
      addressType: 1,
      addressBytes: Uint8Array.of(93, 184, 216, 34),
      port: 8443
    });
    const parsed = new TrHandshakeParser(PASSWORD).push(bytes);
    expect(parsed?.destination).toEqual({ type: "ipv4", host: "93.184.216.34", port: 8443 });
  });

  it("parses IPv6 destinations and compresses zero runs", () => {
    const bytes = trRequest(PASSWORD, {
      addressType: 4,
      addressBytes: Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    });
    const parsed = new TrHandshakeParser(PASSWORD).push(bytes);
    expect(parsed?.destination).toEqual({ type: "ipv6", host: "2001:db8::1", port: 443 });
  });

  it("rejects a password mismatch before opening a tunnel", () => {
    const bytes = trRequest("incorrect-password");
    expect(() => new TrHandshakeParser(PASSWORD).push(bytes)).toThrowError(TrProtocolError);
    try {
      new TrHandshakeParser(PASSWORD).push(bytes);
    } catch (error) {
      expect(error).toMatchObject({ code: "authentication_failed" });
    }
  });

  it("rejects UDP commands because this Worker intentionally implements TCP only", () => {
    const bytes = trRequest(PASSWORD, { command: 3 });
    expect(() => new TrHandshakeParser(PASSWORD).push(bytes)).toThrowError(
      expect.objectContaining({ code: "unsupported_command" })
    );
  });

  it("rejects malformed trailing CRLF and zero destination ports", () => {
    const malformedLine = trRequest(PASSWORD);
    malformedLine[malformedLine.length - 1] = 0;
    expect(() => new TrHandshakeParser(PASSWORD).push(malformedLine)).toThrowError(
      expect.objectContaining({ code: "invalid_header" })
    );

    const zeroPort = trRequest(PASSWORD, { port: 0 });
    expect(() => new TrHandshakeParser(PASSWORD).push(zeroPort)).toThrowError(
      expect.objectContaining({ code: "invalid_port" })
    );
  });

  it("bounds an incomplete header and forbids parser reuse after completion", () => {
    const request = trRequest(PASSWORD, { host: "example.com" });
    const tooSmall = new TrHandshakeParser(PASSWORD, 64);
    expect(() => tooSmall.push(request.subarray(0, 64))).toThrowError(
      expect.objectContaining({ code: "handshake_too_large" })
    );

    const parser = new TrHandshakeParser(PASSWORD);
    parser.push(request);
    expect(() => parser.push(new Uint8Array())).toThrowError(
      expect.objectContaining({ code: "parser_already_complete" })
    );
  });
});
