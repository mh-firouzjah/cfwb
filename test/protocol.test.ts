import { describe, expect, it } from "vitest";
import { createHandshakeDecoder } from "../src/protocol";
import { requestBytes, VALID_UUID } from "./fixtures";
import { trRequest } from "./trojan-fixtures";

const PASSWORD = "unit-test-tr-password";

describe("protocol handshake adapters", () => {
  it("normalizes a VLESS handshake and includes its response header", () => {
    const decoder = createHandshakeDecoder("vl", { uuid: VALID_UUID });
    const payload = Uint8Array.of(1, 2, 3);

    expect(decoder.push(requestBytes({ payload }))).toEqual({
      kind: "complete",
      handshake: {
        destination: { host: "gstatic", port: 443 },
        initialPayload: payload,
        response: Uint8Array.of(0, 0)
      }
    });
  });

  it("normalizes a Trojan handshake without a VLESS response", () => {
    const decoder = createHandshakeDecoder("tr", { password: PASSWORD });
    const payload = Uint8Array.of(0x16, 0x03, 0x01);

    expect(decoder.push(trRequest(PASSWORD, { payload }))).toEqual({
      kind: "complete",
      handshake: {
        destination: { host: "gstatic.com", port: 443 },
        initialPayload: payload
      }
    });
  });

  it("keeps incomplete handshakes distinct from rejected handshakes", () => {
    const decoder = createHandshakeDecoder("vl", { uuid: VALID_UUID });
    expect(decoder.push(Uint8Array.of(0))).toEqual({ kind: "incomplete" });
  });

  it("normalizes authentication, command and malformed-header failures", () => {
    expect(createHandshakeDecoder("tr", { password: PASSWORD }).push(trRequest("wrong-password"))).toEqual({
      kind: "rejected",
      reason: "authentication_failed"
    });
    expect(createHandshakeDecoder("vl", { uuid: VALID_UUID }).push(requestBytes({ command: 2 }))).toEqual({
      kind: "rejected",
      reason: "unsupported_command"
    });
    expect(createHandshakeDecoder("vl", { uuid: VALID_UUID }).push(requestBytes({ version: 1 }))).toEqual({
      kind: "rejected",
      reason: "invalid_request"
    });
  });

  it("rejects invalid credentials during decoder construction", () => {
    expect(() => createHandshakeDecoder("vl", { uuid: "invalid" })).toThrow("UUID secret is invalid");
    expect(() => createHandshakeDecoder("tr", { password: "" })).toThrow(RangeError);
    expect(() => createHandshakeDecoder("tr", { password: "x".repeat(513) })).toThrow(RangeError);
  });
});
