import { describe, expect, it } from "bun:test";

import {
  buildPaytrCallbackHash,
  buildPaytrIframeRequest,
  buildPaytrRefundRequest,
  buildPaytrStatusRequest,
  buildPaytrTransferRequest,
  verifyPaytrCallback,
} from "./paytr-marketplace";

const credentials = {
  merchantId: "100001",
  merchantKey: "merchant-key",
  merchantSalt: "merchant-salt",
};

describe("PayTR marketplace contracts", () => {
  it("builds the documented iframe token payload without card-storage fields", () => {
    const request = buildPaytrIframeRequest(credentials, {
      merchantOid: "KYORDER42ATTEMPT1",
      userIp: "203.0.113.10",
      email: "customer@example.com",
      paymentAmountMinor: 12_345,
      currency: "TL",
      basket: [["Food order #42", "123.45", 1]],
      userName: "Test Customer",
      userAddress: "Kayseri",
      userPhone: "05555555555",
      merchantOkUrl: "https://app.example.com/payment/verifying",
      merchantFailUrl: "https://app.example.com/payment/failed",
      callbackUrl: "https://api.example.com/payments/paytr/callback",
      timeoutLimitMinutes: 15,
      testMode: true,
    });

    expect(request.endpoint).toBe("https://www.paytr.com/odeme/api/get-token");
    expect(request.form.payment_amount).toBe("12345");
    expect(request.form.timeout_limit).toBe("15");
    expect(request.form).not.toHaveProperty("utoken");
    expect(request.form).not.toHaveProperty("ctoken");
    expect(request.form.paytr_token).toBe(
      "LIpk7zLWiauMP2WwpfrRSUx/15qrIDzBy+6ZJbOjn98=",
    );
  });

  it("verifies a callback using a constant-time compatible hash comparison", () => {
    const callback = {
      merchantOid: "KYORDER42ATTEMPT1",
      status: "success" as const,
      totalAmountMinor: 12_345,
    };
    const hash = buildPaytrCallbackHash(credentials, callback);

    expect(verifyPaytrCallback(credentials, { ...callback, hash })).toBe(true);
    expect(verifyPaytrCallback(credentials, { ...callback, hash: `${hash}x` })).toBe(false);
  });

  it("builds status, refund, and platform transfer tokens from documented field order", () => {
    expect(buildPaytrStatusRequest(credentials, "KYORDER42ATTEMPT1").form.paytr_token).toBe(
      "769eRlRngsf5WxLr44H9uBt1qt4gYYpx5RmhpDTGj+M=",
    );
    expect(
      buildPaytrRefundRequest(credentials, {
        merchantOid: "KYORDER42ATTEMPT1",
        returnAmount: "25.00",
        referenceNo: "REFUND42A",
      }).form.paytr_token,
    ).toBe("GXu7jAKnYCw5bIMBzhi/6+GnpPoO575ybJ3O3flLBhY=");
    expect(
      buildPaytrTransferRequest(credentials, {
        merchantOid: "KYORDER42ATTEMPT1",
        transferId: "PAYOUT42A",
        submerchantAmountMinor: 10_212,
        totalAmountMinor: 11_500,
        transferName: "Test Restaurant Ltd",
        transferIban: "TR000000000000000000000000",
      }).form.paytr_token,
    ).toBe("LHA1IXonOdWqsZCvs42cVlE/F+eRI7tAjAE8qX2k+pc=");
  });
});
