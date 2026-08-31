import { describe, expect, it } from "bun:test";

import {
  assertPaymentMethodAvailable,
  activeDiscountedPrices,
  OrderIntakeError,
  parseOrderIntakeInput,
  quoteOrderLines,
  type OrderIntakeInput,
} from "./order-intake";

const validInput: OrderIntakeInput = {
  client_request_id: "c66c8d41-e3ec-4cf4-b63e-cbae1b82fb22",
  venue_id: 12,
  table_id: 31,
  table_number: 4,
  order_source: "qr_table",
  customer_name: "Ada",
  customer_phone: null,
  note: null,
  payment_method: null,
  order_items: [{ product_id: 71, quantity: 2 }],
};

describe("parseOrderIntakeInput", () => {
  it("keeps only server-supported order fields", () => {
    expect(
      parseOrderIntakeInput({
        ...validInput,
        total_amount: 1,
        order_status: "delivered",
        user_id: "forged",
        order_items: [{ product_id: 71, quantity: 2, unit_price: 0.01 }],
      }),
    ).toEqual(validInput);
  });

  it("requires a real table for QR orders", () => {
    expect(() =>
      parseOrderIntakeInput({ ...validInput, table_id: null }),
    ).toThrow(expect.objectContaining({ code: "TABLE_REQUIRED", status: 422 }));
  });

  it("requires a table id whenever a table number is submitted", () => {
    expect(() =>
      parseOrderIntakeInput({
        ...validInput,
        order_source: "direct",
        customer_name: null,
        table_id: null,
      }),
    ).toThrow(expect.objectContaining({ code: "TABLE_REQUIRED", status: 422 }));
  });

  it("rejects duplicate product lines", () => {
    expect(() =>
      parseOrderIntakeInput({
        ...validInput,
        order_items: [
          { product_id: 71, quantity: 1 },
          { product_id: 71, quantity: 1 },
        ],
      }),
    ).toThrow(OrderIntakeError);
  });

  it("accepts only supported checkout payment methods for direct customer orders", () => {
    expect(
      parseOrderIntakeInput({
        ...validInput,
        order_source: "direct",
        table_id: null,
        table_number: 0,
        payment_method: "online",
      }).payment_method,
    ).toBe("online");
    expect(() =>
      parseOrderIntakeInput({
        ...validInput,
        order_source: "direct",
        table_id: null,
        table_number: 0,
        payment_method: "bank_transfer",
      }),
    ).toThrow(expect.objectContaining({ code: "INVALID_PAYMENT_METHOD", status: 422 }));
  });
});

describe("quoteOrderLines", () => {
  it("uses authoritative product prices in integer minor units", () => {
    expect(
      quoteOrderLines(validInput, [
        {
          id: 71,
          venueId: 12,
          price: 62.55,
          isActive: true,
          status: "published",
          isStockTracked: true,
          stockQuantity: 3,
          vatRateBps: 1_000,
        },
      ]),
    ).toEqual({
      lines: [
        {
          product_id: 71,
          quantity: 2,
          unit_price: 62.55,
          unit_price_minor: 6255,
          line_subtotal_minor: 12510,
          vat_rate_bps: 1000,
          vat_amount_minor: 1137,
          is_discounted: false,
        },
      ],
      totalMinor: 12510,
    });
  });

  it("does not reject or reserve stock for marketplace orders", () => {
    expect(
      quoteOrderLines(validInput, [
        {
          id: 71,
          venueId: 12,
          price: 62.55,
          isActive: true,
          status: "published",
          isStockTracked: true,
          stockQuantity: 1,
          vatRateBps: null,
        },
      ]),
    ).toEqual({
      lines: [
        {
          product_id: 71,
          quantity: 2,
          unit_price: 62.55,
          unit_price_minor: 6255,
          line_subtotal_minor: 12510,
          vat_rate_bps: 0,
          vat_amount_minor: 0,
          is_discounted: false,
        },
      ],
      totalMinor: 12510,
    });
  });

  it("snapshots the lowest eligible campaign price before commission is calculated", () => {
    const now = new Date("2026-08-31T12:00:00.000Z");
    const discounts = activeDiscountedPrices(
      [
        {
          product_id: 71,
          discounted_price: 50,
          campaign_id: {
            campaign_status: "active",
            start_datetime: "2026-08-01T00:00:00.000Z",
            end_datetime: "2026-09-30T23:59:59.000Z",
            minimum_order_amount: 100,
            schedule_type: "once",
          },
        },
      ],
      125.1,
      now,
    );
    const quote = quoteOrderLines(
      validInput,
      [
        {
          id: 71,
          venueId: 12,
          price: 62.55,
          isActive: true,
          status: "published",
          isStockTracked: false,
          stockQuantity: null,
          vatRateBps: 1_000,
        },
      ],
      0,
      discounts,
    );

    expect(quote.totalMinor).toBe(10_000);
    expect(quote.lines[0]).toMatchObject({ unit_price_minor: 5_000, is_discounted: true });
  });
});

describe("assertPaymentMethodAvailable", () => {
  const settings = {
    acceptsOnlinePayment: false,
    acceptsCashOnDelivery: true,
    acceptsCardOnDelivery: true,
    onlinePaymentFeatureEnabled: false,
    paytrMarketplaceStatus: "pending",
  } as const;

  it("requires both venue approval and the pilot flag for online payment", () => {
    expect(() => assertPaymentMethodAvailable("online", settings)).toThrow(
      expect.objectContaining({ code: "PAYMENT_METHOD_UNAVAILABLE", status: 422 }),
    );
    expect(() =>
      assertPaymentMethodAvailable("online", {
        ...settings,
        acceptsOnlinePayment: true,
        onlinePaymentFeatureEnabled: true,
        paytrMarketplaceStatus: "approved",
      }),
    ).not.toThrow();
  });

  it("respects each restaurant's cash and card settings", () => {
    expect(() => assertPaymentMethodAvailable("cash", settings)).not.toThrow();
    expect(() =>
      assertPaymentMethodAvailable("card", { ...settings, acceptsCardOnDelivery: false }),
    ).toThrow(expect.objectContaining({ code: "PAYMENT_METHOD_UNAVAILABLE" }));
  });
});
