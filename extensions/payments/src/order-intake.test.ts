import { describe, expect, it } from "bun:test";

import {
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
        },
      ]),
    ).toEqual({
      lines: [{ product_id: 71, quantity: 2, unit_price: 62.55 }],
      totalMinor: 12510,
    });
  });

  it("rejects insufficient tracked stock", () => {
    expect(() =>
      quoteOrderLines(validInput, [
        {
          id: 71,
          venueId: 12,
          price: 62.55,
          isActive: true,
          status: "published",
          isStockTracked: true,
          stockQuantity: 1,
        },
      ]),
    ).toThrow(
      expect.objectContaining({ code: "INSUFFICIENT_STOCK", status: 409 }),
    );
  });
});
