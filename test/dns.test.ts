import { describe, expect, it } from "vitest";
import { resolvePublicDNSWithFetcher, type DNSFetcher } from "../src/dns";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/dns-json" }
  });
}

const NXDOMAIN_FETCHER: DNSFetcher = async (url) =>
  url.searchParams.get("type") === "A"
    ? jsonResponse({ Status: 3 })
    : jsonResponse({ Status: 0, Answer: [{ type: 28, data: "2001:4860:4860::8888" }] });
const HTTP_ERROR_FETCHER: DNSFetcher = async () => jsonResponse({ Status: 0 }, 503);

function responseFetcher(body: unknown): DNSFetcher {
  return async () => jsonResponse(body);
}

describe("Cloudflare DNS-over-HTTPS resolver", () => {
  it("combines and deduplicates bounded A and AAAA answers with safe request options", async () => {
    const controller = new AbortController();
    const calls: Array<{ url: URL; init: RequestInit }> = [];
    const fetcher: DNSFetcher = async (url, init) => {
      calls.push({ url: new URL(url.toString()), init });
      if (url.searchParams.get("type") === "A") {
        return jsonResponse({
          Status: 0,
          Answer: [
            { type: 5, data: "alias.example.net." },
            { type: 1, data: "93.184.216.34" },
            { type: 1, data: "93.184.216.34" }
          ]
        });
      }
      return jsonResponse({ Status: 0, Answer: [{ type: 28, data: "2606:2800:220:1:248:1893:25c8:1946" }] });
    };

    await expect(resolvePublicDNSWithFetcher("example.com", controller.signal, fetcher)).resolves.toEqual([
      "93.184.216.34",
      "2606:2800:220:1:248:1893:25c8:1946"
    ]);
    expect(calls).toHaveLength(2);
    expect(
      calls
        .map(({ url }) => url.searchParams.get("type"))
        .toSorted((left, right) => (left ?? "").localeCompare(right ?? ""))
    ).toEqual(["A", "AAAA"]);
    for (const { url, init } of calls) {
      expect(url.origin + url.pathname).toBe("https://cloudflare-dns.com/dns-query");
      expect(url.searchParams.get("name")).toBe("example.com");
      // Workers' edge Fetch implementation rejects redirect: "error" at
      // runtime. Manual mode exposes any 3xx so query() can fail closed via
      // response.ok without following it.
      expect(init.redirect).toBe("manual");
      expect(new Headers(init.headers).get("Accept")).toBe("application/dns-json");
      expect(init.signal).toBe(controller.signal);
    }
  });

  it("treats NXDOMAIN as no answers while preserving answers from the sibling query", async () => {
    await expect(resolvePublicDNSWithFetcher("example.com", undefined, NXDOMAIN_FETCHER)).resolves.toEqual([
      "2001:4860:4860::8888"
    ]);
  });

  it.each([
    ["missing numeric status", { Answer: [] }, "DNS response is invalid"],
    ["non-success status", { Status: 2 }, "DNS resolution failed"],
    ["non-array answers", { Status: 0, Answer: {} }, "DNS response is invalid"],
    ["malformed answer", { Status: 0, Answer: [{ type: 1, data: 7 }] }, "DNS response is invalid"],
    [
      "too many matching answers",
      {
        Status: 0,
        Answer: Array.from({ length: 17 }, (_, index) => ({ type: 1, data: `93.184.216.${index}` }))
      },
      "DNS response is too large"
    ]
  ])("fails closed for %s", async (_name, body, expectedError) => {
    await expect(resolvePublicDNSWithFetcher("example.com", undefined, responseFetcher(body))).rejects.toThrow(
      expectedError
    );
  });

  it("rejects a non-successful DoH HTTP response", async () => {
    await expect(resolvePublicDNSWithFetcher("example.com", undefined, HTTP_ERROR_FETCHER)).rejects.toThrow(
      "DNS resolution failed"
    );
  });

  it("passes one AbortSignal to both live queries", async () => {
    const controller = new AbortController();
    const signals: AbortSignal[] = [];
    const fetcher: DNSFetcher = (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        if (!(init.signal instanceof AbortSignal)) {
          reject(new Error("missing DNS cancellation signal"));
          return;
        }
        signals.push(init.signal);
        init.signal.addEventListener("abort", () => reject(new DOMException("DNS resolution aborted", "AbortError")), {
          once: true
        });
      });

    const resolution = resolvePublicDNSWithFetcher("example.com", controller.signal, fetcher);
    expect(signals).toEqual([controller.signal, controller.signal]);
    controller.abort();

    await expect(resolution).rejects.toMatchObject({ name: "AbortError" });
  });
});
