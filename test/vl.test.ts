import { describe, expect, it } from "vitest";
import {
  authenticateVlUser,
  buildVlResponseHeader,
  MAX_HANDSHAKE_BYTES,
  parseVlUUID,
  VlHandshakeParser,
  VlProtocolError,
  type VLProtocolErrorCode
} from "../src/protocol/vl";
import fixtures from "./fixtures/vl-v0.json";
import { requestBytes, VALID_UUID_BYTES } from "./fixtures";

function hexBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error("fixture hex is invalid");
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function parse(bytes: Uint8Array) {
  const parsed = new VlHandshakeParser().push(bytes);
  expect(parsed).toBeDefined();
  return parsed!;
}

function expectCodeForParserReuse(parser: VlHandshakeParser): void {
  expect(() => parser.push(new Uint8Array())).toThrowError(
    expect.objectContaining({ code: "parser_already_complete" })
  );
}

function xorshift32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function expectCode(bytes: Uint8Array, code: VLProtocolErrorCode, maximumBytes?: number): void {
  try {
    new VlHandshakeParser(maximumBytes).push(bytes);
  } catch (error) {
    expect(error).toBeInstanceOf(VlProtocolError);
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`expected VL protocol error: ${code}`);
}

describe("VLESS version-0 protocol", () => {
  it("parses a domain destination and coalesced payload", () => {
    const payload = Uint8Array.from([0x16, 0x03, 0x01]);
    const result = parse(requestBytes({ payload }));
    expect(result.request).toMatchObject({
      version: 0,
      command: "tcp",
      destination: { host: "gstatic", port: 443 }
    });
    expect(result.request.userId).toEqual(VALID_UUID_BYTES);
    expect(result.initialPayload).toEqual(payload);
  });

  it("parses IPv4 and IPv6 destinations", () => {
    const ipv4 = parse(requestBytes({ addressType: 1, address: Uint8Array.from([203, 0, 113, 7]) }));
    expect(ipv4.request.destination).toEqual({ host: "203.0.113.7", port: 443 });

    const ipv6 = parse(
      requestBytes({
        addressType: 3,
        address: Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
      })
    );
    expect(ipv6.request.destination).toEqual({ host: "2001:db8::1", port: 443 });
  });

  it("supports fragmented handshakes and preserves coalesced payload", () => {
    const bytes = requestBytes({ payload: Uint8Array.of(1, 2, 3) });
    const parser = new VlHandshakeParser();
    expect(parser.push(bytes.subarray(0, 1))).toBeUndefined();
    expect(parser.push(bytes.subarray(1, 17))).toBeUndefined();
    expect(parser.push(bytes.subarray(17))?.initialPayload).toEqual(Uint8Array.of(1, 2, 3));
  });

  it("accepts every split point in a valid handshake", () => {
    const bytes = requestBytes({ payload: Uint8Array.of(1, 2, 3) });
    const headerLength = bytes.length - 3;
    for (let split = 1; split < headerLength; split += 1) {
      const parser = new VlHandshakeParser();
      expect(parser.push(bytes.subarray(0, split))).toBeUndefined();
      expect(parser.push(bytes.subarray(split))?.initialPayload).toEqual(Uint8Array.of(1, 2, 3));
    }
  });

  it.each([
    ["nonzero add-on length", requestBytes({ addons: Uint8Array.of(0xaa, 0xbb) }), "unsupported_addons"],
    ["unsupported version", requestBytes({ version: 1 }), "unsupported_version"],
    ["UDP command", requestBytes({ command: 2 }), "unsupported_command"],
    ["Mux command", requestBytes({ command: 3 }), "unsupported_command"],
    ["unknown address type", requestBytes({ addressType: 9 }), "invalid_address_type"],
    ["zero port", requestBytes({ port: 0 }), "invalid_port"],
    ["empty domain", requestBytes({ address: Uint8Array.of(0) }), "invalid_domain"],
    ["invalid domain character", requestBytes({ address: Uint8Array.from([3, 0x61, 0x40, 0x62]) }), "invalid_domain"]
  ] as const)("rejects a request with %s", (_name, bytes, code) => {
    expectCode(bytes, code);
  });

  it("waits for truncated addresses and enforces the handshake size limit", () => {
    const truncated = requestBytes({ addressType: 1, address: Uint8Array.from([192, 0]) });
    expect(new VlHandshakeParser().push(truncated)).toBeUndefined();

    const tooLarge = Uint8Array.from([
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
    expectCode(tooLarge, "handshake_too_large", 64);
  });

  it("matches the configured UUID format and parses it into 16 bytes", () => {
    const userId = parseVlUUID("00000000-0000-4000-8000-000000000001");
    expect(userId).toHaveLength(16);
    expect(userId).toEqual(
      Uint8Array.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
    );
    expect(() => parseVlUUID("not-a-uuid")).toThrow("UUID secret is invalid");
    expect(() => parseVlUUID("00000000-0000-0000-0000-000000000000")).toThrow("UUID secret is invalid");
  });

  it("authenticates only an exact matching 16-byte user ID before returning a request", () => {
    const expected = parseVlUUID("00000000-0000-4000-8000-000000000001");
    const oversized = new Uint8Array(17);
    oversized.set(expected);

    expect(authenticateVlUser(expected.slice(), expected)).toBe(true);
    expect(authenticateVlUser(expected.slice().fill(1), expected)).toBe(false);
    expect(authenticateVlUser(expected.subarray(1), expected)).toBe(false);
    expect(authenticateVlUser(oversized, expected)).toBe(false);
    expect(authenticateVlUser(expected, expected.subarray(0, 15))).toBe(false);

    const mismatched = expected.slice();
    mismatched[15] = mismatched[15]! ^ 1;
    expect(() => new VlHandshakeParser(1024, expected).push(requestBytes({ uuid: mismatched }))).toThrowError(
      expect.objectContaining({ code: "authentication_failed" })
    );
    expect(new VlHandshakeParser(1024, expected).push(requestBytes({ uuid: expected }))?.request.userId).toEqual(
      expected
    );
  });

  it("emits the protocol response header", () => {
    expect(buildVlResponseHeader()).toEqual(hexBytes(fixtures.response_header_hex));
  });

  for (const fixture of fixtures.cases) {
    for (const fragmentation of fixture.fragmentations) {
      it(`parses fixture ${fixture.name} with ${fragmentation.name} fragmentation`, () => {
        const wire = hexBytes(fixture.wire_hex);
        const parser = new VlHandshakeParser();
        let offset = 0;
        let parsed: ReturnType<VlHandshakeParser["push"]>;
        const subsequentPayload: Uint8Array[] = [];
        for (const chunkSize of fragmentation.chunk_sizes) {
          const chunk = wire.subarray(offset, offset + chunkSize);
          if (parsed === undefined) {
            parsed = parser.push(chunk);
          } else {
            subsequentPayload.push(chunk.slice());
          }
          offset += chunkSize;
        }

        expect(offset).toBe(wire.length);
        expect(parsed).toBeDefined();
        expect(parsed?.request.destination).toEqual({
          host: fixture.host,
          port: fixture.port
        });
        const payloadLength =
          (parsed?.initialPayload.byteLength ?? 0) +
          subsequentPayload.reduce((total, chunk) => total + chunk.byteLength, 0);
        const payload = new Uint8Array(payloadLength);
        let payloadOffset = 0;
        if (parsed !== undefined) {
          payload.set(parsed.initialPayload, payloadOffset);
          payloadOffset += parsed.initialPayload.byteLength;
        }
        for (const chunk of subsequentPayload) {
          payload.set(chunk, payloadOffset);
          payloadOffset += chunk.byteLength;
        }
        expect(payload).toEqual(hexBytes(fixture.initial_payload_hex));
      });
    }
  }

  it("rejects parser reuse after a completed handshake", () => {
    const parser = new VlHandshakeParser();
    parser.push(requestBytes());
    expectCodeForParserReuse(parser);
  });

  it("keeps deterministic mutations of valid handshakes inside the protocol error boundary", () => {
    const random = xorshift32(0xc0ffee);
    const valid = requestBytes({ payload: Uint8Array.of(1, 2, 3, 4) });

    for (let caseIndex = 0; caseIndex < 1_000; caseIndex += 1) {
      const bytes = valid.slice();
      const mutations = 1 + (random() % 4);
      for (let mutation = 0; mutation < mutations; mutation += 1) {
        const offset = random() % bytes.byteLength;
        bytes[offset] = bytes[offset]! ^ (random() & 0xff || 1);
      }

      const parser = new VlHandshakeParser();
      let offset = 0;
      try {
        while (offset < bytes.byteLength) {
          const fragmentLength = 1 + (random() % 47);
          const parsed = parser.push(bytes.subarray(offset, offset + fragmentLength));
          offset += fragmentLength;
          if (parsed !== undefined) {
            expect(parsed.request.destination.port).toBeGreaterThan(0);
            expect(parsed.request.destination.port).toBeLessThanOrEqual(65_535);
            expect(parsed.request.destination.host.length).toBeGreaterThan(0);
            expect(parsed.initialPayload).toBeInstanceOf(Uint8Array);
            break;
          }
        }
      } catch (error) {
        expect(error).toBeInstanceOf(VlProtocolError);
      }
    }
  });
});
