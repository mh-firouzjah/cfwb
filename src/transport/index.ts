import type { Destination } from "../contracts";

/** Reasons a session can be asked to terminate. */
export type SessionCloseReason =
  | "normal"
  | "invalid_request"
  | "authentication_failed"
  | "unsupported_command"
  | "tcp_failed"
  | "handshake_timeout"
  | "transport_failed";

/** Identifies failures originating inside a byte-stream transport adapter. */
export class ByteStreamTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ByteStreamTransportError";
  }
}

/** A transport-neutral, ordered byte stream with an explicit full-close signal. */
export interface ByteStreamTransport {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  /** Resolves when the peer or adapter terminates the whole transport. */
  readonly closed: Promise<void>;
  close(reason: SessionCloseReason): void;
}

/** An established upstream byte-stream connection. */
export interface UpstreamConnection {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  close(): Promise<void>;
}

/** Opens the upstream connection; aborting the signal must cancel a pending open. */
export type Connector = (destination: Destination, signal: AbortSignal) => Promise<UpstreamConnection>;
