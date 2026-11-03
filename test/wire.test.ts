import { describe, expect, it } from "vitest";
import { decodeDomain, formatIPv4, formatIPv6 } from "../src/protocol/wire";

const encode = (value: string): Uint8Array => new TextEncoder().encode(value);
const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);
const ipv6 = (...groups: number[]): Uint8Array =>
  Uint8Array.from(groups.flatMap((group) => [group >> 8, group & 0xff]));

describe("wire helpers", () => {
  it.each([
    [ipv6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), "2001:db8::1"],
    [ipv6(0, 0, 0, 0, 0, 0, 0, 1), "::1"],
    [ipv6(0, 0, 0, 0, 0, 0, 0, 0), "::"],
    [ipv6(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1), "2001:db8:0:1::1"],
    [ipv6(0x2001, 0xdb8, 0, 1, 1, 1, 1, 1), "2001:db8:0:1:1:1:1:1"],
    [ipv6(1, 0, 0, 2, 0, 0, 3, 4), "1::2:0:0:3:4"],
    [ipv6(0xfe80, 0, 0, 0, 0, 0, 0, 0), "fe80::"]
  ])("formats IPv6 per RFC 5952", (input, expected) => {
    expect(formatIPv6(input)).toBe(expected);
  });

  it("rejects wrong address lengths", () => {
    expect(() => formatIPv6(new Uint8Array(15))).toThrow(RangeError);
    expect(() => formatIPv4(new Uint8Array(5))).toThrow(RangeError);
    expect(formatIPv4(bytes(93, 184, 216, 34))).toBe("93.184.216.34");
  });

  it("accepts plain hostnames including underscores and rejects everything else", () => {
    expect(decodeDomain(encode("_dmarc.Example-1.com."))).toBe("_dmarc.Example-1.com.");
    expect(decodeDomain(new Uint8Array())).toBeUndefined();
    expect(decodeDomain(encode("a@b"))).toBeUndefined();
    expect(decodeDomain(encode("a:443"))).toBeUndefined();
    expect(decodeDomain(encode("ü.example"))).toBeUndefined();
    expect(decodeDomain(Uint8Array.of(0xc3, 0x28))).toBeUndefined();
    expect(decodeDomain(Uint8Array.of(0xef, 0xbb, 0xbf, ...encode("example.com")))).toBeUndefined();
  });
});
