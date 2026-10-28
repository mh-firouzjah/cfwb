import ranges from "./data/cloudflare-ranges.json";
import type { VlDestination } from "./protocol/vl";

export type DestinationPolicyErrorCode =
  | "invalid_address"
  | "blocked_address"
  | "cloudflare_address"
  | "invalid_domain"
  | "self_destination"
  | "port_not_allowed"
  | "dns_resolution_failed";

export class DestinationPolicyError extends Error {
  readonly code: DestinationPolicyErrorCode;

  constructor(code: DestinationPolicyErrorCode) {
    super("destination is not permitted");
    this.name = "DestinationPolicyError";
    this.code = code;
  }
}

export interface DestinationPolicy {
  expectedHost: string;
}

export interface ResolvedDestination {
  hostname: string;
  port: number;
}

export type DNSResolver = (hostname: string, signal?: AbortSignal) => Promise<readonly string[]>;

interface IPv4Range {
  network: number;
  mask: number;
}

function ipv4Number(bytes: readonly number[]): number {
  return (((bytes[0]! << 24) >>> 0) + (bytes[1]! << 16) + (bytes[2]! << 8) + bytes[3]!) >>> 0;
}

function ipv4Range(cidr: string): IPv4Range {
  const [address, prefixText] = cidr.split("/");
  const bytes = address!.split(".").map(Number);
  const prefix = Number(prefixText);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: ipv4Number(bytes) & mask, mask };
}

const BLOCKED_IPV4 = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "168.63.129.16/32",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/3"
].map(ipv4Range);

const CLOUDFLARE_IPV4 = [...ranges.ipv4, ...ranges.resolver].map(ipv4Range);

function parseIPv4(value: string): number[] | undefined {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  const bytes: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return undefined;
    const byte = Number(part);
    if (byte > 255) return undefined;
    bytes.push(byte);
  }
  return bytes;
}

function parseIPv6Part(part: string): number[] | undefined {
  if (part === "") return [];
  const tokens = part.split(":");
  const words: number[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.includes(".")) {
      if (index !== tokens.length - 1) return undefined;
      const ipv4 = parseIPv4(token);
      if (ipv4 === undefined) return undefined;
      words.push((ipv4[0]! << 8) | ipv4[1]!, (ipv4[2]! << 8) | ipv4[3]!);
    } else {
      if (!/^[0-9a-f]{1,4}$/i.test(token)) return undefined;
      words.push(Number.parseInt(token, 16));
    }
  }
  return words;
}

function parseIPv6(value: string): Uint8Array | undefined {
  if (value.includes("%")) return undefined;
  const marker = value.indexOf("::");
  if (marker !== -1 && value.indexOf("::", marker + 1) !== -1) return undefined;
  const leftText = marker === -1 ? value : value.slice(0, marker);
  const rightText = marker === -1 ? "" : value.slice(marker + 2);
  const left = parseIPv6Part(leftText);
  const right = parseIPv6Part(rightText);
  if (left === undefined || right === undefined) return undefined;

  let words: number[];
  if (marker === -1) {
    if (left.length !== 8) return undefined;
    words = left;
  } else {
    const zeros = 8 - left.length - right.length;
    if (zeros < 1) return undefined;
    words = [...left, ...Array.from({ length: zeros }, () => 0), ...right];
  }
  const bytes = new Uint8Array(16);
  for (let index = 0; index < words.length; index += 1) {
    bytes[index * 2] = words[index]! >>> 8;
    bytes[index * 2 + 1] = words[index]! & 0xff;
  }
  return bytes;
}

function inIPv4Range(address: number, range: IPv4Range): boolean {
  return (address & range.mask) === range.network;
}

function prefixMatches(bytes: Uint8Array, prefix: Uint8Array, length: number): boolean {
  const wholeBytes = Math.floor(length / 8);
  for (let index = 0; index < wholeBytes; index += 1) {
    if (bytes[index] !== prefix[index]) return false;
  }
  const remaining = length % 8;
  if (remaining === 0) return true;
  const mask = (0xff << (8 - remaining)) & 0xff;
  return (bytes[wholeBytes]! & mask) === (prefix[wholeBytes]! & mask);
}

interface IPv6Range {
  readonly prefix: Uint8Array;
  readonly length: number;
}

function ipv6Range(address: string, length: number): IPv6Range {
  const prefix = parseIPv6(address);
  if (prefix === undefined) throw new Error("static IPv6 policy range is invalid");
  return { prefix, length };
}

const CLOUDFLARE_IPV6: readonly IPv6Range[] = ranges.ipv6.map((cidr) => {
  const [address, prefixText] = cidr.split("/");
  return ipv6Range(address!, Number(prefixText));
});

// Only special-use prefixes inside the permitted 2000::/3 space need explicit entries.
const BLOCKED_IPV6: readonly IPv6Range[] = [
  ipv6Range("2001::", 23),
  ipv6Range("2001:db8::", 32),
  ipv6Range("2002::", 16),
  ipv6Range("3fff::", 20)
];

export function assertAllowedIPAddress(address: string): void {
  const ipv4 = parseIPv4(address);
  if (ipv4 !== undefined) {
    const value = ipv4Number(ipv4);
    if (BLOCKED_IPV4.some((range) => inIPv4Range(value, range))) {
      throw new DestinationPolicyError("blocked_address");
    }
    if (CLOUDFLARE_IPV4.some((range) => inIPv4Range(value, range))) {
      throw new DestinationPolicyError("cloudflare_address");
    }
    return;
  }

  const ipv6 = parseIPv6(address);
  if (ipv6 === undefined) throw new DestinationPolicyError("invalid_address");

  const mapped = ipv6.subarray(0, 10).every((byte) => byte === 0) && ipv6[10] === 0xff && ipv6[11] === 0xff;
  const compatible = ipv6.subarray(0, 12).every((byte) => byte === 0);
  if (mapped || compatible) {
    const mappedIPv4 = Array.from(ipv6.subarray(12)).join(".");
    assertAllowedIPAddress(mappedIPv4);
    return;
  }

  // Conservatively permit global unicast (2000::/3), excluding documentation and Cloudflare ranges.
  if ((ipv6[0]! & 0xe0) !== 0x20 || BLOCKED_IPV6.some(({ prefix, length }) => prefixMatches(ipv6, prefix, length))) {
    throw new DestinationPolicyError("blocked_address");
  }
  if (CLOUDFLARE_IPV6.some(({ prefix, length }) => prefixMatches(ipv6, prefix, length))) {
    throw new DestinationPolicyError("cloudflare_address");
  }
}

export function validateDomainName(domain: string, expectedHost: string): string {
  const normalized = domain.toLowerCase();
  const normalizedExpected = expectedHost.toLowerCase().replace(/\.$/, "");
  if (normalized.length > 253 || normalized.includes("@") || normalized.includes(":") || normalized.endsWith(".")) {
    throw new DestinationPolicyError("invalid_domain");
  }
  const labels = normalized.split(".");
  if (labels.length < 2 || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new DestinationPolicyError("invalid_domain");
  }
  const blockedSuffixes = [".localhost", ".local", ".localdomain", ".internal", ".home", ".lan", ".onion"];
  if (normalized === "localhost" || blockedSuffixes.some((suffix) => normalized.endsWith(suffix))) {
    throw new DestinationPolicyError("invalid_domain");
  }
  if (normalized === normalizedExpected) throw new DestinationPolicyError("self_destination");
  return normalized;
}

export async function resolveAndValidateDestination(
  destination: VlDestination,
  policy: DestinationPolicy,
  resolver: DNSResolver,
  signal?: AbortSignal
): Promise<ResolvedDestination> {
  if (
    !Number.isInteger(destination.port) ||
    destination.port < 1 ||
    destination.port > 65535 ||
    destination.port === 25
  ) {
    throw new DestinationPolicyError("port_not_allowed");
  }
  if (destination.type !== "domain") {
    assertAllowedIPAddress(destination.host);
    return { hostname: destination.host, port: destination.port };
  }

  const domain = validateDomainName(destination.host, policy.expectedHost);
  let addresses: readonly string[];
  try {
    addresses = await resolver(domain, signal);
  } catch {
    throw new DestinationPolicyError("dns_resolution_failed");
  }
  if (addresses.length === 0) throw new DestinationPolicyError("dns_resolution_failed");
  // Evaluate every DNS answer independently.
  // Skip prohibited or malformed addresses and select the first allowed one.
  // Reject the destination only if no allowed address remains.
  let cloudflareAnswerSeen = false;
  let blockedAddressSeen = false;
  let invalidAddressSeen = false;
  let firstPublicAddress: string | undefined;

  for (const address of addresses) {
    try {
      assertAllowedIPAddress(address);
      firstPublicAddress ??= address;
    } catch (error) {
      if (!(error instanceof DestinationPolicyError)) {
        throw error;
      }

      switch (error.code) {
        case "cloudflare_address":
          cloudflareAnswerSeen = true;
          break;

        case "blocked_address":
          blockedAddressSeen = true;
          break;

        case "invalid_address":
          invalidAddressSeen = true;
          break;

        default:
          throw error;
      }
    }
  }

  if (firstPublicAddress !== undefined) {
    return { hostname: firstPublicAddress, port: destination.port };
  }

  if (blockedAddressSeen) {
    throw new DestinationPolicyError("blocked_address");
  }

  if (invalidAddressSeen) {
    throw new DestinationPolicyError("invalid_address");
  }

  if (cloudflareAnswerSeen) {
    throw new DestinationPolicyError("cloudflare_address");
  }

  throw new DestinationPolicyError("dns_resolution_failed");
}
