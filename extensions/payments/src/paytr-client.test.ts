import { describe, expect, it } from "bun:test";

import {
  normalizePaytrCurrency,
  parsePaytrAmountToMinor,
  PaytrMarketplaceClient,
} from "./paytr-client";

const credentials = {
  merchantId: "merchant",
  merchantKey: "key",
  merchantSalt: "salt",
};

describe("PayTR status response normalization", () => {
  it("converts documented comma-decimal amounts to integer minor units", () => {
    expect(parsePaytrAmountToMinor("10,8")).toBe(1080);
    expect(parsePaytrAmountToMinor("125.05")).toBe(12505);
  });

  it("rejects ambiguous or over-precise amounts", () => {
    expect(() => parsePaytrAmountToMinor("1,000.00")).toThrow();
    expect(() => parsePaytrAmountToMinor("10.001")).toThrow();
  });

  it("normalizes PayTR's TL alias without accepting unknown currencies", () => {
    expect(normalizePaytrCurrency("TL")).toBe("TRY");
    expect(normalizePaytrCurrency("TRY")).toBe("TRY");
    expect(() => normalizePaytrCurrency("BTC")).toThrow();
  });
});

describe("PayTR command failure certainty", () => {
  it("marks a provider rejection as definite", async () => {
    const client = new PaytrMarketplaceClient(
      credentials,
      async () => Response.json({ status: "failed", err_no: "12", err_msg: "Rejected" }),
    );

    await expect(
      client.refund({ merchantOid: "KYO42A7", returnAmount: "10.00" }),
    ).rejects.toMatchObject({ definitelyRejected: true, providerCode: "12" });
  });

  it("keeps transport errors uncertain", async () => {
    const client = new PaytrMarketplaceClient(credentials, async () => {
      throw new Error("connection reset");
    });

    await expect(
      client.refund({ merchantOid: "KYO42A7", returnAmount: "10.00" }),
    ).rejects.toMatchObject({ definitelyRejected: false, providerCode: null });
  });
});
