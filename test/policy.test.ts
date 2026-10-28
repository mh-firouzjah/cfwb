import { describe, expect, it } from "vitest";
import {
  DestinationPolicyError,
  assertAllowedIPAddress,
  resolveAndValidateDestination,
  validateDomainName
} from "../src/policy";
import ranges from "../src/data/cloudflare-ranges.json";

function ipv4LastAddress(cidr: string): string {
  const [address, prefixText] = cidr.split("/");
  const start = address!.split(".").reduce((value, part) => (value << 8n) | BigInt(part), 0n);
  const size = 1n << BigInt(32 - Number(prefixText));
  const last = start + size - 1n;
  return [24n, 16n, 8n, 0n].map((shift) => Number((last >> shift) & 255n)).join(".");
}

function ipv6BigInt(address: string): bigint {
  const halves = address.split("::");
  const left = halves[0] === "" ? [] : halves[0]!.split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]!.split(":");
  const groups = halves.length === 1 ? left : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group || "0"}`), 0n);
}

function ipv6Address(value: bigint): string {
  return Array.from({ length: 8 }, (_, index) => {
    const shift = BigInt((7 - index) * 16);
    return ((value >> shift) & 0xffffn).toString(16).padStart(4, "0");
  }).join(":");
}

function ipv6LastAddress(cidr: string): string {
  const [address, prefixText] = cidr.split("/");
  const prefix = BigInt(prefixText!);
  const last = ipv6BigInt(address!) + (1n << (128n - prefix)) - 1n;
  return ipv6Address(last);
}

const policy = { expectedHost: "edge.example.com" };

describe("destination policy", () => {
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "168.63.129.16",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "2001::1",
    "2001:db8::1",
    "2002::1",
    "3fff::1",
    "5f00::1",
    "64:ff9b::808:808",
    "64:ff9b:1::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1"
  ])("blocks non-public address %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
  });

  it.each(["8.8.8.8", "9.9.9.9", "2001:4860:4860::8888"])("allows public address %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).not.toThrow();
  });

  it.each([...ranges.ipv4, ...ranges.resolver].map((cidr) => cidr.split("/")[0]!))(
    "blocks the start of Cloudflare IPv4 range %s",
    (address) => {
      expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
    }
  );

  it.each([...ranges.ipv4, ...ranges.resolver].map(ipv4LastAddress))(
    "blocks the end of Cloudflare IPv4 range %s",
    (address) => {
      expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
    }
  );

  it.each(ranges.ipv6.map((cidr) => cidr.split("/")[0]!))("blocks the start of Cloudflare IPv6 range %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
  });

  it.each(ranges.ipv6.map(ipv6LastAddress))("blocks the end of Cloudflare IPv6 range %s", (address) => {
    expect(() => assertAllowedIPAddress(address)).toThrow(DestinationPolicyError);
  });

  it.each(["localhost", "a.localhost", "metadata.google.internal", "user@example.com", "a..example", "-bad.example"])(
    "rejects unsafe domain %s",
    (domain) => expect(() => validateDomainName(domain, "edge.example.com")).toThrow(DestinationPolicyError)
  );

  it("rejects the Worker hostname case-insensitively", () => {
    expect(() => validateDomainName("EDGE.EXAMPLE.COM", "edge.example.com")).toThrow(DestinationPolicyError);
  });

  it.each([1, 22, 53, 80, 443, 587, 8443, 65535])("permits valid outbound TCP port %d", async (port) => {
    await expect(
      resolveAndValidateDestination({ type: "ipv4", host: "93.184.216.34", port }, policy, async () => [])
    ).resolves.toEqual({ hostname: "93.184.216.34", port });
  });

  it.each([0, 25, 65536, 1.5])("rejects invalid or platform-blocked TCP port %d", async (port) => {
    await expect(
      resolveAndValidateDestination({ type: "ipv4", host: "93.184.216.34", port }, policy, async () => [])
    ).rejects.toMatchObject({ code: "port_not_allowed" });
  });

  it("pins a domain to a validated resolver result", async () => {
    const result = await resolveAndValidateDestination(
      { type: "domain", host: "example.com", port: 443 },
      policy,
      async () => ["93.184.216.34"]
    );
    expect(result).toEqual({ hostname: "93.184.216.34", port: 443 });
  });

  it("skips private DNS answers when a public address is available", async () => {
    await expect(
      resolveAndValidateDestination(
        { type: "domain", host: "example.com", port: 443 },
        { expectedHost: "worker.example.com" },
        async () => ["10.0.0.1", "93.184.216.34"]
      )
    ).resolves.toEqual({
      hostname: "93.184.216.34",
      port: 443
    });
  });

  it("skips Cloudflare DNS answers and selects a reachable public answer", async () => {
    const result = await resolveAndValidateDestination(
      { type: "domain", host: "example.com", port: 443 },
      policy,
      async () => ["104.16.0.1", "93.184.216.34"]
    );
    expect(result).toEqual({ hostname: "93.184.216.34", port: 443 });
  });

  it("rejects a domain when every DNS answer is Cloudflare-owned", async () => {
    await expect(
      resolveAndValidateDestination({ type: "domain", host: "example.com", port: 443 }, policy, async () => [
        "104.16.0.1",
        "172.64.0.1"
      ])
    ).rejects.toMatchObject({ code: "cloudflare_address" });
  });

  it("rejects malformed addresses returned by DNS", async () => {
    await expect(
      resolveAndValidateDestination({ type: "domain", host: "example.com", port: 443 }, policy, async () => ["bad"])
    ).rejects.toMatchObject({ code: "invalid_address" });
  });

  it("rejects DNS lookup failures", async () => {
    await expect(
      resolveAndValidateDestination({ type: "domain", host: "example.com", port: 443 }, policy, async () => {
        throw new Error("resolver unavailable");
      })
    ).rejects.toMatchObject({ code: "dns_resolution_failed" });
  });

  it("rejects empty DNS results", async () => {
    await expect(
      resolveAndValidateDestination({ type: "domain", host: "example.com", port: 443 }, policy, async () => [])
    ).rejects.toMatchObject({ code: "dns_resolution_failed" });
  });

  it("skips blocked and malformed DNS answers when a public address is available", async () => {
    await expect(
      resolveAndValidateDestination(
        { type: "domain", host: "example.com", port: 443 },
        { expectedHost: "worker.example.com" },
        async () => ["192.168.1.10", "not-an-ip", "93.184.216.34"]
      )
    ).resolves.toEqual({
      hostname: "93.184.216.34",
      port: 443
    });
  });

  it("rejects when all DNS answers are private or reserved", async () => {
    await expect(
      resolveAndValidateDestination(
        { type: "domain", host: "example.com", port: 443 },
        { expectedHost: "worker.example.com" },
        async () => ["10.0.0.1", "192.168.1.10"]
      )
    ).rejects.toThrow(DestinationPolicyError);
  });
});
