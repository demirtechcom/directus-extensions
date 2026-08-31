import { createHmac, timingSafeEqual } from "node:crypto";

type AttemptStatus = "pending" | "succeeded" | "failed" | "expired" | "refunded";
type PaymentStatus = AttemptStatus;

export function createMerchantOid(orderId: number, attemptId: number): string {
  assertPositiveInteger("orderId", orderId);
  assertPositiveInteger("attemptId", attemptId);
  return `KYO${orderId}A${attemptId}`;
}

export function canOpenPaymentAttempt(
  attempts: readonly { status: AttemptStatus }[],
): boolean {
  const latest = attempts.at(-1);
  return !latest || latest.status === "failed" || latest.status === "expired";
}

export function applyVerifiedPaymentCallback(
  payment: {
    status: PaymentStatus;
    amountMinor: number;
    currency: string;
  },
  attempt: {
    id: number;
    status: "pending" | "succeeded" | "failed" | "expired" | "refunded";
    amountMinor: number;
    currency: string;
  },
  callback: {
    status: "success" | "failed";
    amountMinor: number;
    currency: string;
    occurredAt: string;
  },
): {
  outcome: "captured" | "failed" | "duplicate" | "excess_capture";
  paymentStatus: "pending" | "succeeded" | "failed";
  attemptStatus: "succeeded" | "failed";
  orderStatus: "awaiting_payment" | "pending";
  acceptanceDeadlineAt: string | null;
  refundExcessAttempt: boolean;
} {
  if (callback.amountMinor !== attempt.amountMinor || callback.amountMinor !== payment.amountMinor) {
    throw new Error("Callback amount does not match payment attempt");
  }
  if (callback.currency !== attempt.currency || callback.currency !== payment.currency) {
    throw new Error("Callback currency does not match payment attempt");
  }

  if (attempt.status === "succeeded" && payment.status === "succeeded") {
    return {
      outcome: "duplicate",
      paymentStatus: "succeeded",
      attemptStatus: "succeeded",
      orderStatus: "pending",
      acceptanceDeadlineAt: null,
      refundExcessAttempt: false,
    };
  }

  if (callback.status === "failed") {
    return {
      outcome: "failed",
      paymentStatus: "failed",
      attemptStatus: "failed",
      orderStatus: "awaiting_payment",
      acceptanceDeadlineAt: null,
      refundExcessAttempt: false,
    };
  }

  if (payment.status === "succeeded") {
    return {
      outcome: "excess_capture",
      paymentStatus: "succeeded",
      attemptStatus: "succeeded",
      orderStatus: "pending",
      acceptanceDeadlineAt: null,
      refundExcessAttempt: true,
    };
  }

  const occurredAt = parseTimestamp("callback.occurredAt", callback.occurredAt);
  return {
    outcome: "captured",
    paymentStatus: "succeeded",
    attemptStatus: "succeeded",
    orderStatus: "pending",
    acceptanceDeadlineAt: new Date(occurredAt + 5 * 60 * 1_000).toISOString(),
    refundExcessAttempt: false,
  };
}

export function evaluatePaymentWindow(input: {
  expiresAt: string;
  now: string;
  providerCaptured: boolean;
}): "pending" | "captured" | "expired" {
  const expiresAt = parseTimestamp("expiresAt", input.expiresAt);
  const now = parseTimestamp("now", input.now);
  if (now < expiresAt) return "pending";
  return input.providerCaptured ? "captured" : "expired";
}

export function evaluateAcceptanceTimeout(input: {
  orderStatus: "awaiting_payment" | "pending" | "preparing" | "delivered" | "cancelled";
  paymentStatus:
    | "pending"
    | "succeeded"
    | "failed"
    | "expired"
    | "partially_refunded"
    | "refunded";
  acceptanceDeadlineAt: string | null;
  now: string;
}): { cancel: boolean; refund: boolean } {
  if (
    input.orderStatus !== "pending" ||
    !["succeeded", "partially_refunded"].includes(input.paymentStatus) ||
    input.acceptanceDeadlineAt === null
  ) {
    return { cancel: false, refund: false };
  }
  const deadline = parseTimestamp("acceptanceDeadlineAt", input.acceptanceDeadlineAt);
  const now = parseTimestamp("now", input.now);
  return now >= deadline ? { cancel: true, refund: true } : { cancel: false, refund: false };
}

export function acceptanceTimeoutRefundIdempotencyKey(
  orderId: number,
  failedRefundCount: number,
): string {
  assertPositiveInteger("orderId", orderId);
  if (!Number.isSafeInteger(failedRefundCount) || failedRefundCount < 0) {
    throw new Error("failedRefundCount must be a non-negative integer");
  }
  return failedRefundCount === 0
    ? `acceptance-timeout-${orderId}`
    : `acceptance-timeout-${orderId}-retry-${failedRefundCount}`;
}

export function canRevealDeliveryCode(paymentStatus: string, orderStatus: string): boolean {
  return (
    ["succeeded", "partially_refunded"].includes(paymentStatus) &&
    ["pending", "preparing"].includes(orderStatus)
  );
}

export function providerCommandFailureDisposition(input: {
  providerAccepted: boolean;
  providerRejected: boolean;
}): "failed" | "pending_reconciliation" {
  return !input.providerAccepted && input.providerRejected ? "failed" : "pending_reconciliation";
}

export function payoutRequiresBalanceAdjustment(status: string): boolean {
  return ["instruction_pending", "submitted", "succeeded"].includes(status);
}

export function hashDeliveryCode(
  orderId: number,
  code: string,
  pepper: string,
): string {
  assertPositiveInteger("orderId", orderId);
  if (!/^\d{6}$/.test(code)) {
    throw new Error("Delivery code must contain exactly six digits");
  }
  if (!pepper) throw new Error("Delivery code pepper is required");
  return createHmac("sha256", pepper).update(`${orderId}:${code}`).digest("hex");
}

export function deriveDeliveryCode(orderId: number, pepper: string): string {
  assertPositiveInteger("orderId", orderId);
  if (!pepper) throw new Error("Delivery code pepper is required");
  const digest = createHmac("sha256", pepper).update(`delivery:${orderId}`).digest();
  return (digest.readUInt32BE(0) % 1_000_000).toString().padStart(6, "0");
}

export function verifyDeliveryCode(
  orderId: number,
  code: string,
  pepper: string,
  expectedHash: string,
): boolean {
  try {
    const actual = Buffer.from(hashDeliveryCode(orderId, code, pepper), "hex");
    const expected = Buffer.from(expectedHash, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
}

function parseTimestamp(name: string, value: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error(`${name} must be an ISO timestamp`);
  return timestamp;
}
