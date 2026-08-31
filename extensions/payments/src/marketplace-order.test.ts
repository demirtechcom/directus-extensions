import { describe, expect, it } from "bun:test";

import {
  applyVerifiedPaymentCallback,
  canOpenPaymentAttempt,
  canRevealDeliveryCode,
  createMerchantOid,
  deriveDeliveryCode,
  evaluateAcceptanceTimeout,
  evaluatePaymentWindow,
  hashDeliveryCode,
  providerCommandFailureDisposition,
  payoutRequiresBalanceAdjustment,
  acceptanceTimeoutRefundIdempotencyKey,
  verifyDeliveryCode,
} from "./marketplace-order";

describe("marketplace payment attempts", () => {
  it("uses the durable attempt id to create a retry-safe merchant order id", () => {
    expect(createMerchantOid(42, 7)).toBe("KYO42A7");
  });

  it("does not open a retry before the previous attempt is reconciled", () => {
    expect(canOpenPaymentAttempt([])).toBe(true);
    expect(canOpenPaymentAttempt([{ status: "pending" }])).toBe(false);
    expect(canOpenPaymentAttempt([{ status: "succeeded" }])).toBe(false);
    expect(canOpenPaymentAttempt([{ status: "failed" }])).toBe(true);
    expect(canOpenPaymentAttempt([{ status: "expired" }])).toBe(true);
  });
});

describe("applyVerifiedPaymentCallback", () => {
  const payment = {
    status: "pending" as const,
    amountMinor: 11_500,
    currency: "TRY",
  };
  const attempt = {
    id: 7,
    status: "pending" as const,
    amountMinor: 11_500,
    currency: "TRY",
  };

  it("promotes an online order only after amount and currency match", () => {
    const result = applyVerifiedPaymentCallback(payment, attempt, {
      status: "success",
      amountMinor: 11_500,
      currency: "TRY",
      occurredAt: "2026-08-31T10:00:00.000Z",
    });

    expect(result).toEqual({
      outcome: "captured",
      paymentStatus: "succeeded",
      attemptStatus: "succeeded",
      orderStatus: "pending",
      acceptanceDeadlineAt: "2026-08-31T10:05:00.000Z",
      refundExcessAttempt: false,
    });
  });

  it("rejects a successful callback whose amount or currency differs", () => {
    expect(() =>
      applyVerifiedPaymentCallback(payment, attempt, {
        status: "success",
        amountMinor: 11_499,
        currency: "TRY",
        occurredAt: "2026-08-31T10:00:00.000Z",
      }),
    ).toThrow("Callback amount does not match payment attempt");
    expect(() =>
      applyVerifiedPaymentCallback(payment, attempt, {
        status: "success",
        amountMinor: 11_500,
        currency: "USD",
        occurredAt: "2026-08-31T10:00:00.000Z",
      }),
    ).toThrow("Callback currency does not match payment attempt");
  });

  it("treats a repeated callback as idempotent", () => {
    expect(
      applyVerifiedPaymentCallback(
        { ...payment, status: "succeeded" },
        { ...attempt, status: "succeeded" },
        {
          status: "success",
          amountMinor: 11_500,
          currency: "TRY",
          occurredAt: "2026-08-31T10:00:00.000Z",
        },
      ).outcome,
    ).toBe("duplicate");
  });

  it("marks a second successful attempt for automatic full refund", () => {
    const result = applyVerifiedPaymentCallback(
      { ...payment, status: "succeeded" },
      attempt,
      {
        status: "success",
        amountMinor: 11_500,
        currency: "TRY",
        occurredAt: "2026-08-31T10:00:00.000Z",
      },
    );

    expect(result.outcome).toBe("excess_capture");
    expect(result.refundExcessAttempt).toBe(true);
  });
});

describe("payment and acceptance deadlines", () => {
  it("keeps a payment pending before its 15 minute window ends", () => {
    expect(
      evaluatePaymentWindow({
        expiresAt: "2026-08-31T10:15:00.000Z",
        now: "2026-08-31T10:14:59.000Z",
        providerCaptured: false,
      }),
    ).toBe("pending");
  });

  it("captures a late callback found by status query and otherwise expires", () => {
    expect(
      evaluatePaymentWindow({
        expiresAt: "2026-08-31T10:15:00.000Z",
        now: "2026-08-31T10:15:00.000Z",
        providerCaptured: true,
      }),
    ).toBe("captured");
    expect(
      evaluatePaymentWindow({
        expiresAt: "2026-08-31T10:15:00.000Z",
        now: "2026-08-31T10:15:00.000Z",
        providerCaptured: false,
      }),
    ).toBe("expired");
  });

  it("cancels and refunds when the venue misses the five minute acceptance deadline", () => {
    expect(
      evaluateAcceptanceTimeout({
        orderStatus: "pending",
        paymentStatus: "succeeded",
        acceptanceDeadlineAt: "2026-08-31T10:05:00.000Z",
        now: "2026-08-31T10:05:00.000Z",
      }),
    ).toEqual({ cancel: true, refund: true });

    expect(
      evaluateAcceptanceTimeout({
        orderStatus: "pending",
        paymentStatus: "partially_refunded",
        acceptanceDeadlineAt: "2026-08-31T10:05:00.000Z",
        now: "2026-08-31T10:05:00.000Z",
      }),
    ).toEqual({ cancel: true, refund: true });
  });

  it("uses a new idempotency key only after a definite acceptance-timeout refund failure", () => {
    expect(acceptanceTimeoutRefundIdempotencyKey(42, 0)).toBe("acceptance-timeout-42");
    expect(acceptanceTimeoutRefundIdempotencyKey(42, 1)).toBe("acceptance-timeout-42-retry-1");
  });
});

describe("delivery verification", () => {
  it("keeps the delivery code available after a partial refund", () => {
    expect(canRevealDeliveryCode("succeeded", "pending")).toBe(true);
    expect(canRevealDeliveryCode("partially_refunded", "preparing")).toBe(true);
    expect(canRevealDeliveryCode("refunded", "preparing")).toBe(false);
    expect(canRevealDeliveryCode("succeeded", "delivered")).toBe(false);
  });

  it("derives a stable six digit code without storing the plaintext", () => {
    const code = deriveDeliveryCode(42, "delivery-pepper");

    expect(code).toMatch(/^\d{6}$/);
    expect(deriveDeliveryCode(42, "delivery-pepper")).toBe(code);
    expect(deriveDeliveryCode(43, "delivery-pepper")).not.toBe(code);
  });

  it("stores only a salted delivery-code hash and verifies exactly six digits", () => {
    const hash = hashDeliveryCode(42, "381204", "server-pepper");

    expect(hash).toBe("0638ff04651100ca500765984eac7bc47f2d02dc74d764850351cc3d18f2aef4");
    expect(verifyDeliveryCode(42, "381204", "server-pepper", hash)).toBe(true);
    expect(verifyDeliveryCode(42, "381205", "server-pepper", hash)).toBe(false);
    expect(() => hashDeliveryCode(42, "12345", "server-pepper")).toThrow(
      "Delivery code must contain exactly six digits",
    );
  });
});

describe("provider command failure handling", () => {
  it("allows retry only after a definite provider rejection", () => {
    expect(
      providerCommandFailureDisposition({ providerAccepted: false, providerRejected: true }),
    ).toBe("failed");
    expect(
      providerCommandFailureDisposition({ providerAccepted: false, providerRejected: false }),
    ).toBe("pending_reconciliation");
  });

  it("requires reconciliation after the provider accepted a command", () => {
    expect(
      providerCommandFailureDisposition({ providerAccepted: true, providerRejected: true }),
    ).toBe("pending_reconciliation");
  });

  it("treats an uncertain transfer as already sent when allocating a refund", () => {
    expect(payoutRequiresBalanceAdjustment("instruction_pending")).toBe(true);
    expect(payoutRequiresBalanceAdjustment("submitted")).toBe(true);
    expect(payoutRequiresBalanceAdjustment("succeeded")).toBe(true);
    expect(payoutRequiresBalanceAdjustment("scheduled")).toBe(false);
    expect(payoutRequiresBalanceAdjustment("failed")).toBe(false);
  });
});
