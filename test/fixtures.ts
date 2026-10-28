export const VALID_UUID = "00112233-4455-6677-8899-aabbccddeeff";

export const VALID_UUID_BYTES = Uint8Array.from([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
]);

export function requestBytes(
  options: {
    version?: number;
    uuid?: Uint8Array;
    addons?: Uint8Array;
    command?: number;
    port?: number;
    addressType?: number;
    address?: Uint8Array;
    payload?: Uint8Array;
  } = {}
): Uint8Array {
  const uuid = options.uuid ?? VALID_UUID_BYTES;
  const addons = options.addons ?? new Uint8Array();
  const address = options.address ?? Uint8Array.from([7, ...new TextEncoder().encode("example")]);
  const payload = options.payload ?? new Uint8Array();
  const port = options.port ?? 443;
  return Uint8Array.from([
    options.version ?? 0,
    ...uuid,
    addons.length,
    ...addons,
    options.command ?? 1,
    (port >>> 8) & 0xff,
    port & 0xff,
    options.addressType ?? 2,
    ...address,
    ...payload
  ]);
}
