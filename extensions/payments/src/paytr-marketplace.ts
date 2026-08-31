export interface PaytrCredentials {
  merchantId: string;
  merchantKey: string;
  merchantSalt: string;
}

export interface PaytrRequest {
  endpoint: string;
  form: Record<string, string>;
}

export interface PaytrIframeInput {
  merchantOid: string;
  userIp: string;
  email: string;
  paymentAmountMinor: number;
  currency: string;
  basket: readonly [string, string, number][];
  userName: string;
  userAddress: string;
  userPhone: string;
  merchantOkUrl: string;
  merchantFailUrl: string;
  callbackUrl: string;
  timeoutLimitMinutes: number;
  testMode: boolean;
}

export interface PaytrCallbackInput {
  merchantOid: string;
  status: "success" | "failed";
  totalAmountMinor: number;
}

export interface PaytrRefundInput {
  merchantOid: string;
  returnAmount: string;
  referenceNo?: string;
}

export interface PaytrTransferInput {
  merchantOid: string;
  transferId: string;
  submerchantAmountMinor: number;
  totalAmountMinor: number;
  transferName: string;
  transferIban: string;
}

export function buildPaytrIframeRequest(
  credentials: PaytrCredentials,
  input: PaytrIframeInput,
): PaytrRequest {
  assertCredentials(credentials);
  assertMerchantOid(input.merchantOid);
  assertMinor(input.paymentAmountMinor);
  if (!Number.isInteger(input.timeoutLimitMinutes) || input.timeoutLimitMinutes <= 0) {
    throw new Error("timeoutLimitMinutes must be a positive integer");
  }

  const userBasket = Buffer.from(JSON.stringify(input.basket)).toString("base64");
  const testMode = input.testMode ? "1" : "0";
  const noInstallment = "1";
  const maxInstallment = "0";
  const tokenInput =
    credentials.merchantId +
    input.userIp +
    input.merchantOid +
    input.email +
    input.paymentAmountMinor +
    userBasket +
    noInstallment +
    maxInstallment +
    input.currency +
    testMode +
    credentials.merchantSalt;

  return {
    endpoint: "https://www.paytr.com/odeme/api/get-token",
    form: {
      merchant_id: credentials.merchantId,
      user_ip: input.userIp,
      merchant_oid: input.merchantOid,
      email: input.email,
      payment_amount: String(input.paymentAmountMinor),
      paytr_token: hmac(credentials.merchantKey, tokenInput),
      user_basket: userBasket,
      debug_on: testMode,
      no_installment: noInstallment,
      max_installment: maxInstallment,
      currency: input.currency,
      test_mode: testMode,
      user_name: input.userName,
      user_address: input.userAddress,
      user_phone: input.userPhone,
      merchant_ok_url: input.merchantOkUrl,
      merchant_fail_url: input.merchantFailUrl,
      merchant_notify_url: input.callbackUrl,
      timeout_limit: String(input.timeoutLimitMinutes),
      lang: "tr",
    },
  };
}

export function buildPaytrCallbackHash(
  credentials: PaytrCredentials,
  input: PaytrCallbackInput,
): string {
  assertCredentials(credentials);
  assertMerchantOid(input.merchantOid);
  assertMinor(input.totalAmountMinor);
  return hmac(
    credentials.merchantKey,
    `${input.merchantOid}${credentials.merchantSalt}${input.status}${input.totalAmountMinor}`,
  );
}

export function verifyPaytrCallback(
  credentials: PaytrCredentials,
  input: PaytrCallbackInput & { hash: string },
): boolean {
  const expected = Buffer.from(buildPaytrCallbackHash(credentials, input));
  const received = Buffer.from(input.hash);
  return expected.length === received.length && timingSafeEqual(expected, received);
}

export function buildPaytrStatusRequest(
  credentials: PaytrCredentials,
  merchantOid: string,
): PaytrRequest {
  assertCredentials(credentials);
  assertMerchantOid(merchantOid);
  return {
    endpoint: "https://www.paytr.com/odeme/durum-sorgu",
    form: {
      merchant_id: credentials.merchantId,
      merchant_oid: merchantOid,
      paytr_token: hmac(
        credentials.merchantKey,
        `${credentials.merchantId}${merchantOid}${credentials.merchantSalt}`,
      ),
    },
  };
}

export function buildPaytrRefundRequest(
  credentials: PaytrCredentials,
  input: PaytrRefundInput,
): PaytrRequest {
  assertCredentials(credentials);
  assertMerchantOid(input.merchantOid);
  if (!/^\d+\.\d{2}$/.test(input.returnAmount)) {
    throw new Error("returnAmount must use a dot and exactly two decimals");
  }
  if (input.referenceNo && !/^[A-Za-z0-9]{1,64}$/.test(input.referenceNo)) {
    throw new Error("referenceNo must be at most 64 alphanumeric characters");
  }
  return {
    endpoint: "https://www.paytr.com/odeme/iade",
    form: {
      merchant_id: credentials.merchantId,
      merchant_oid: input.merchantOid,
      return_amount: input.returnAmount,
      paytr_token: hmac(
        credentials.merchantKey,
        `${credentials.merchantId}${input.merchantOid}${input.returnAmount}${credentials.merchantSalt}`,
      ),
      ...(input.referenceNo ? { reference_no: input.referenceNo } : {}),
    },
  };
}

export function buildPaytrTransferRequest(
  credentials: PaytrCredentials,
  input: PaytrTransferInput,
): PaytrRequest {
  assertCredentials(credentials);
  assertMerchantOid(input.merchantOid);
  assertMinor(input.submerchantAmountMinor);
  assertMinor(input.totalAmountMinor);
  if (!/^[A-Za-z0-9]{1,60}$/.test(input.transferId)) {
    throw new Error("transferId must be at most 60 alphanumeric characters");
  }
  if (!/^TR\d{24}$/.test(input.transferIban.replaceAll(" ", ""))) {
    throw new Error("transferIban must be a Turkish IBAN");
  }
  const transferIban = input.transferIban.replaceAll(" ", "");
  const tokenInput = `${credentials.merchantId}${input.merchantOid}${input.transferId}${input.submerchantAmountMinor}${input.totalAmountMinor}${input.transferName}${transferIban}${credentials.merchantSalt}`;
  return {
    endpoint: "https://www.paytr.com/odeme/platform/transfer",
    form: {
      merchant_id: credentials.merchantId,
      merchant_oid: input.merchantOid,
      trans_id: input.transferId,
      submerchant_amount: String(input.submerchantAmountMinor),
      total_amount: String(input.totalAmountMinor),
      transfer_name: input.transferName,
      transfer_iban: transferIban,
      paytr_token: hmac(credentials.merchantKey, tokenInput),
    },
  };
}

function hmac(key: string, input: string): string {
  return createHmac("sha256", key).update(input).digest("base64");
}

function assertCredentials(credentials: PaytrCredentials): void {
  if (!credentials.merchantId || !credentials.merchantKey || !credentials.merchantSalt) {
    throw new Error("PayTR credentials are incomplete");
  }
}

function assertMerchantOid(value: string): void {
  if (!/^[A-Za-z0-9]{1,64}$/.test(value)) {
    throw new Error("merchantOid must be at most 64 alphanumeric characters");
  }
}

function assertMinor(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error("PayTR amount must be a positive integer minor amount");
  }
}
import { createHmac, timingSafeEqual } from "node:crypto";
