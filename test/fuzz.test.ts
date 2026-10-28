import { describe, expect, it } from "vitest";
import { VlHandshakeParser, VlProtocolError } from "../src/protocol/vl";

function xorshift32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

describe("bounded malformed-input fuzz corpus", () => {
  it("never escapes the protocol error boundary", () => {
    const random = xorshift32(0xc0ffee);
    for (let caseIndex = 0; caseIndex < 2_000; caseIndex += 1) {
      const length = random() % 1_500;
      const bytes = new Uint8Array(length);
      for (let index = 0; index < bytes.length; index += 1) bytes[index] = random() & 0xff;
      const parser = new VlHandshakeParser();
      try {
        let offset = 0;
        while (offset < bytes.length) {
          const fragmentLength = Math.max(1, random() % 47);
          const result = parser.push(bytes.subarray(offset, offset + fragmentLength));
          offset += fragmentLength;
          if (result !== undefined) break;
        }
      } catch (error) {
        expect(error).toBeInstanceOf(VlProtocolError);
      }
    }
  });
});
