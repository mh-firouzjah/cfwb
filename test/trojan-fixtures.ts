import { sha224Hex } from "../src/protocol/tr";

const encoder = new TextEncoder();

export function trRequest(
  password: string,
  options: {
    readonly host?: string;
    readonly port?: number;
    readonly command?: number;
    readonly payload?: Uint8Array;
    readonly addressType?: 1 | 3 | 4;
    readonly addressBytes?: Uint8Array;
  } = {}
): Uint8Array {
  const addressType = options.addressType ?? 3;
  const addressBytes = options.addressBytes ?? encoder.encode(options.host ?? "example.com");
  const port = options.port ?? 443;
  const header = Uint8Array.from([
    ...encoder.encode(sha224Hex(encoder.encode(password))),
    0x0d,
    0x0a,
    options.command ?? 1,
    addressType,
    ...(addressType === 3 ? [addressBytes.byteLength] : []),
    ...addressBytes,
    (port >>> 8) & 0xff,
    port & 0xff,
    0x0d,
    0x0a
  ]);
  const payload = options.payload ?? new Uint8Array();
  const request = new Uint8Array(header.byteLength + payload.byteLength);
  request.set(header);
  request.set(payload, header.byteLength);
  return request;
}
