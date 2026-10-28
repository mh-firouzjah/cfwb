import type { DNSResolver } from "./policy";

interface DNSAnswer {
  readonly type: number;
  readonly data: string;
}

export type DNSFetcher = (url: URL, init: RequestInit) => Promise<Response>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseAnswers(value: unknown, expectedType: 1 | 28): string[] {
  if (!isRecord(value) || typeof value.Status !== "number") throw new Error("DNS response is invalid");
  if (value.Status === 3) return [];
  if (value.Status !== 0) throw new Error("DNS resolution failed");
  if (value.Answer === undefined) return [];
  if (!Array.isArray(value.Answer)) throw new Error("DNS response is invalid");

  const answers: string[] = [];
  for (const item of value.Answer) {
    if (!isRecord(item) || typeof item.type !== "number" || typeof item.data !== "string") {
      throw new Error("DNS response is invalid");
    }
    const answer: DNSAnswer = { type: item.type, data: item.data };
    if (answer.type === expectedType) answers.push(answer.data);
    if (answers.length > 16) throw new Error("DNS response is too large");
  }
  return answers;
}

async function query(
  hostname: string,
  type: 1 | 28,
  signal: AbortSignal | undefined,
  fetcher: DNSFetcher
): Promise<string[]> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("name", hostname);
  url.searchParams.set("type", type === 1 ? "A" : "AAAA");
  const response = await fetcher(url, {
    headers: { Accept: "application/dns-json" },
    // Workers' edge Fetch implementation does not implement "error" mode.
    // "manual" prevents following redirects; the response.ok check below
    // rejects every exposed 3xx response.
    redirect: "manual",
    signal
  });
  if (!response.ok) throw new Error("DNS resolution failed");
  const body: unknown = await response.json<unknown>();
  return parseAnswers(body, type);
}

export async function resolvePublicDNSWithFetcher(
  hostname: string,
  signal: AbortSignal | undefined,
  fetcher: DNSFetcher
): Promise<string[]> {
  const [ipv4, ipv6] = await Promise.all([query(hostname, 1, signal, fetcher), query(hostname, 28, signal, fetcher)]);
  return Array.from(new Set([...ipv4, ...ipv6]));
}

export const resolvePublicDNS: DNSResolver = async (hostname, signal) => {
  return await resolvePublicDNSWithFetcher(hostname, signal, fetch);
};
