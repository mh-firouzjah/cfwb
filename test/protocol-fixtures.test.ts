import { describe, expect, it } from "vitest";
import { buildVlResponseHeader, VlHandshakeParser } from "../src/protocol/vl";
import fixtures from "./fixtures/vl-v0.json";

function hexBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error("fixture hex is invalid");
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

describe("VL version-0 fixtures", () => {
  it("emits the expected response bytes", () => {
    expect(buildVlResponseHeader()).toEqual(hexBytes(fixtures.response_header_hex));
  });

  for (const fixture of fixtures.cases) {
    for (const fragmentation of fixture.fragmentations) {
      it(`parses ${fixture.name} with ${fragmentation.name} fragmentation byte-for-byte`, () => {
        const wire = hexBytes(fixture.wire_hex);
        const parser = new VlHandshakeParser();
        let offset = 0;
        let parsed;
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
          type: fixture.address_type,
          host: fixture.host,
          port: fixture.port
        });
        const combinedPayload = new Uint8Array(
          (parsed?.initialPayload.length ?? 0) + subsequentPayload.reduce((total, chunk) => total + chunk.length, 0)
        );
        let payloadOffset = 0;
        if (parsed !== undefined) {
          combinedPayload.set(parsed.initialPayload, payloadOffset);
          payloadOffset += parsed.initialPayload.length;
        }
        for (const chunk of subsequentPayload) {
          combinedPayload.set(chunk, payloadOffset);
          payloadOffset += chunk.length;
        }
        expect(combinedPayload).toEqual(hexBytes(fixture.initial_payload_hex));
      });
    }
  }
});
