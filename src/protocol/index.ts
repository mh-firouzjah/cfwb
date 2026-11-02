import { TrHandshakeParser, TrProtocolError } from "./tr";
import { buildVlResponseHeader, parseVlUUID, VlHandshakeParser, VlProtocolError } from "./vl";
import type { Destination } from "../contracts";

export type { Destination } from "../contracts";

export type ProtocolMode = "vl" | "tr";

export interface ProtocolCredentials {
  readonly uuid?: string;
  readonly password?: string;
}

export type HandshakeRejection = "authentication_failed" | "unsupported_command" | "invalid_request";

export interface ParsedHandshake {
  readonly destination: Destination;
  readonly initialPayload: Uint8Array;
  readonly response?: Uint8Array;
}

export type HandshakeResult =
  | { readonly kind: "incomplete" }
  | { readonly kind: "complete"; readonly handshake: ParsedHandshake }
  | { readonly kind: "rejected"; readonly reason: HandshakeRejection };

/** The only protocol-facing contract consumed by the transport-independent Session. */
export interface HandshakeDecoder {
  push(chunk: Uint8Array): HandshakeResult;
}

const INCOMPLETE: HandshakeResult = { kind: "incomplete" };

function rejectionFor(error: unknown): HandshakeResult | undefined {
  if (!(error instanceof VlProtocolError) && !(error instanceof TrProtocolError)) return undefined;
  if (error.code === "authentication_failed") return { kind: "rejected", reason: "authentication_failed" };
  if (error.code === "unsupported_command") return { kind: "rejected", reason: "unsupported_command" };
  return { kind: "rejected", reason: "invalid_request" };
}

/** Adapts one wire protocol parser to the common handshake contract. Throws on invalid credentials. */
export function createHandshakeDecoder(mode: ProtocolMode, credentials: ProtocolCredentials): HandshakeDecoder {
  if (mode === "vl") {
    if (credentials.uuid === undefined) throw new Error("vl credential is required");
    const parser = new VlHandshakeParser(undefined, parseVlUUID(credentials.uuid));
    const response = buildVlResponseHeader();

    return {
      push(chunk): HandshakeResult {
        try {
          const parsed = parser.push(chunk);
          if (parsed === undefined) return INCOMPLETE;
          return {
            kind: "complete",
            handshake: { destination: parsed.request.destination, initialPayload: parsed.initialPayload, response }
          };
        } catch (error) {
          const rejection = rejectionFor(error);
          if (rejection !== undefined) return rejection;
          throw error;
        }
      }
    };
  }

  if (credentials.password === undefined) throw new Error("tr credential is required");
  const parser = new TrHandshakeParser(credentials.password);

  return {
    push(chunk): HandshakeResult {
      try {
        const parsed = parser.push(chunk);
        if (parsed === undefined) return INCOMPLETE;
        return {
          kind: "complete",
          handshake: { destination: parsed.destination, initialPayload: parsed.initialPayload }
        };
      } catch (error) {
        const rejection = rejectionFor(error);
        if (rejection !== undefined) return rejection;
        throw error;
      }
    }
  };
}
