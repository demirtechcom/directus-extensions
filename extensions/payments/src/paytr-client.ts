import {
  buildPaytrIframeRequest,
  buildPaytrRefundRequest,
  buildPaytrStatusRequest,
  buildPaytrTransferRequest,
  type PaytrCredentials,
  type PaytrIframeInput,
  type PaytrRefundInput,
  type PaytrRequest,
  type PaytrTransferInput,
} from "./paytr-marketplace.js";

export interface PaytrPaymentStatus {
  captured: boolean;
  amountMinor: number | null;
  currency: string | null;
  paymentType: string | null;
  paidAt: string | null;
  errorCode: string | null;
}

export interface PaytrCommandResult {
  reference: string | null;
  providerStatus: string;
}

export class PaytrProviderError extends Error {
  constructor(
    message: string,
    readonly providerCode: string | null = null,
    readonly definitelyRejected = false,
  ) {
    super(message);
    this.name = "PaytrProviderError";
  }
}

export class PaytrMarketplaceClient {
  constructor(
    private readonly credentials: PaytrCredentials,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async createIframe(input: PaytrIframeInput): Promise<{ token: string }> {
    const response = await this.post(buildPaytrIframeRequest(this.credentials, input));
    if (response.status !== "success" || typeof response.token !== "string" || !response.token) {
      throw providerFailure("PayTR rejected the iFrame request", response);
    }
    return { token: response.token };
  }

  async queryStatus(merchantOid: string): Promise<PaytrPaymentStatus> {
    const response = await this.post(buildPaytrStatusRequest(this.credentials, merchantOid));
    if (response.status !== "success") {
      const errorCode = optionalString(response.err_no);
      if (errorCode === "004") {
        return {
          captured: false,
          amountMinor: null,
          currency: null,
          paymentType: null,
          paidAt: null,
          errorCode,
        };
      }
      throw providerFailure("PayTR status query failed", response);
    }
    return {
      captured: true,
      amountMinor: parsePaytrAmountToMinor(response.payment_amount),
      currency: normalizePaytrCurrency(response.currency),
      paymentType: optionalString(response.odeme_tipi),
      paidAt: optionalString(response.payment_date),
      errorCode: null,
    };
  }

  async refund(input: PaytrRefundInput): Promise<PaytrCommandResult> {
    const response = await this.post(buildPaytrRefundRequest(this.credentials, input));
    if (response.status !== "success") {
      throw providerFailure("PayTR refund failed", response);
    }
    return {
      reference: optionalString(response.return_ref_num) ?? input.referenceNo ?? null,
      providerStatus: "success",
    };
  }

  async transfer(input: PaytrTransferInput): Promise<PaytrCommandResult> {
    const response = await this.post(buildPaytrTransferRequest(this.credentials, input));
    if (response.status !== "success") {
      throw providerFailure("PayTR transfer failed", response);
    }
    return {
      reference: optionalString(response.trans_id) ?? input.transferId,
      providerStatus: "success",
    };
  }

  private async post(request: PaytrRequest): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await this.fetchImpl(request.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(request.form).toString(),
      });
    } catch (error: unknown) {
      throw new PaytrProviderError(
        error instanceof Error ? `PayTR request failed: ${error.message}` : "PayTR request failed",
      );
    }
    if (!response.ok) {
      throw new PaytrProviderError(`PayTR responded with HTTP ${response.status}`);
    }
    const body: unknown = await response.json();
    if (!isRecord(body)) {
      throw new PaytrProviderError("PayTR returned an invalid JSON response");
    }
    return body;
  }
}

export function parsePaytrAmountToMinor(value: unknown): number {
  if (typeof value !== "string" && typeof value !== "number") {
    throw new PaytrProviderError("PayTR amount is missing");
  }
  const normalized = String(value).trim().replace(",", ".");
  if (!/^\d+(?:\.\d{1,2})?$/.test(normalized)) {
    throw new PaytrProviderError("PayTR amount has an invalid format");
  }
  const [whole, fraction = ""] = normalized.split(".");
  const amount = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new PaytrProviderError("PayTR amount is outside the supported range");
  }
  return amount;
}

export function normalizePaytrCurrency(value: unknown): string {
  if (typeof value !== "string") {
    throw new PaytrProviderError("PayTR currency is missing");
  }
  const currency = value.trim().toUpperCase() === "TL" ? "TRY" : value.trim().toUpperCase();
  if (!["TRY", "EUR", "USD", "GBP", "RUB"].includes(currency)) {
    throw new PaytrProviderError("PayTR currency is unsupported");
  }
  return currency;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function providerFailure(
  message: string,
  response: Record<string, unknown>,
): PaytrProviderError {
  const code = optionalString(response.err_no);
  const reason = optionalString(response.err_msg) ?? optionalString(response.reason);
  return new PaytrProviderError(reason ? `${message}: ${reason}` : message, code, true);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
