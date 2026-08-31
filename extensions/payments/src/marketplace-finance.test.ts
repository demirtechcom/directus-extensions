import { describe, expect, it } from "bun:test";

import {
  allocatePayoutOffsets,
  calculateMarketplaceSettlement,
  calculatePayoutAfterRefunds,
  calculateRefundLineAmount,
  allocatePartialRefund,
} from "./marketplace-finance";

describe("calculateMarketplaceSettlement", () => {
  it("calculates commission from discounted food and leaves delivery to the venue", () => {
    const result = calculateMarketplaceSettlement({
      foodSubtotalMinor: 10_000,
      deliveryFeeMinor: 1_500,
      commissionRateBps: 1_000,
      commissionVatRateBps: 2_000,
      withholdingRateBps: 100,
      vatBreakdown: [
        { grossMinor: 6_000, vatRateBps: 1_000 },
        { grossMinor: 4_000, vatRateBps: 2_000 },
      ],
    });

    expect(result).toEqual({
      grossMinor: 11_500,
      commissionMinor: 1_000,
      commissionVatMinor: 200,
      foodVatMinor: 1_212,
      withholdingMinor: 88,
      venuePayoutMinor: 10_212,
    });
  });

  it("rounds every monetary component to an integer minor unit", () => {
    const result = calculateMarketplaceSettlement({
      foodSubtotalMinor: 999,
      deliveryFeeMinor: 0,
      commissionRateBps: 333,
      commissionVatRateBps: 2_000,
      withholdingRateBps: 100,
      vatBreakdown: [{ grossMinor: 999, vatRateBps: 1_000 }],
    });

    expect(result.commissionMinor).toBe(33);
    expect(result.commissionVatMinor).toBe(7);
    expect(result.foodVatMinor).toBe(91);
    expect(result.withholdingMinor).toBe(9);
    expect(result.venuePayoutMinor).toBe(950);
  });

  it("rejects a VAT breakdown that does not equal the discounted food subtotal", () => {
    expect(() =>
      calculateMarketplaceSettlement({
        foodSubtotalMinor: 1_000,
        deliveryFeeMinor: 0,
        commissionRateBps: 1_000,
        commissionVatRateBps: 2_000,
        withholdingRateBps: 100,
        vatBreakdown: [{ grossMinor: 999, vatRateBps: 1_000 }],
      }),
    ).toThrow("VAT breakdown must equal food subtotal");
  });
});

describe("allocatePartialRefund", () => {
  it("reduces the venue payout and commission proportionally for a food refund", () => {
    const result = allocatePartialRefund({
      refundFoodMinor: 2_500,
      refundDeliveryMinor: 0,
      originalFoodMinor: 10_000,
      originalCommissionMinor: 1_000,
      originalCommissionVatMinor: 200,
      originalWithholdingMinor: 88,
    });

    expect(result).toEqual({
      refundTotalMinor: 2_500,
      commissionReversalMinor: 250,
      commissionVatReversalMinor: 50,
      withholdingReversalMinor: 22,
      venueDebitMinor: 2_178,
    });
  });

  it("assigns a delivery refund entirely to the venue", () => {
    const result = allocatePartialRefund({
      refundFoodMinor: 0,
      refundDeliveryMinor: 500,
      originalFoodMinor: 10_000,
      originalCommissionMinor: 1_000,
      originalCommissionVatMinor: 200,
      originalWithholdingMinor: 88,
    });

    expect(result.venueDebitMinor).toBe(500);
  });

  it("uses cumulative food refunds to keep rounded fee reversals within the original fees", () => {
    const first = allocatePartialRefund({
      refundFoodMinor: 1,
      refundDeliveryMinor: 0,
      originalFoodMinor: 3,
      originalCommissionMinor: 1,
      originalCommissionVatMinor: 1,
      originalWithholdingMinor: 1,
    });
    const second = allocatePartialRefund({
      refundFoodMinor: 1,
      refundDeliveryMinor: 0,
      originalFoodMinor: 3,
      originalCommissionMinor: 1,
      originalCommissionVatMinor: 1,
      originalWithholdingMinor: 1,
      previousRefundFoodMinor: 1,
      previousCommissionReversalMinor: first.commissionReversalMinor,
      previousCommissionVatReversalMinor: first.commissionVatReversalMinor,
      previousWithholdingReversalMinor: first.withholdingReversalMinor,
    });
    const final = allocatePartialRefund({
      refundFoodMinor: 1,
      refundDeliveryMinor: 0,
      originalFoodMinor: 3,
      originalCommissionMinor: 1,
      originalCommissionVatMinor: 1,
      originalWithholdingMinor: 1,
      previousRefundFoodMinor: 2,
      previousCommissionReversalMinor:
        first.commissionReversalMinor + second.commissionReversalMinor,
      previousCommissionVatReversalMinor:
        first.commissionVatReversalMinor + second.commissionVatReversalMinor,
      previousWithholdingReversalMinor:
        first.withholdingReversalMinor + second.withholdingReversalMinor,
    });

    expect(
      first.commissionReversalMinor + second.commissionReversalMinor + final.commissionReversalMinor,
    ).toBe(1);
    expect(
      first.commissionVatReversalMinor +
        second.commissionVatReversalMinor +
        final.commissionVatReversalMinor,
    ).toBe(1);
    expect(
      first.withholdingReversalMinor +
        second.withholdingReversalMinor +
        final.withholdingReversalMinor,
    ).toBe(1);
  });
});

describe("calculateRefundLineAmount", () => {
  it("uses the order snapshot price and remaining refundable quantity", () => {
    expect(
      calculateRefundLineAmount({
        purchasedQuantity: 3,
        previouslyClaimedQuantity: 1,
        requestedQuantity: 2,
        unitPriceMinor: 1_250,
      }),
    ).toBe(2_500);
  });

  it("rejects a repeated product refund beyond the purchased quantity", () => {
    expect(() =>
      calculateRefundLineAmount({
        purchasedQuantity: 2,
        previouslyClaimedQuantity: 2,
        requestedQuantity: 1,
        unitPriceMinor: 1_250,
      }),
    ).toThrow("Refund item quantity exceeds the remaining quantity");
  });
});

describe("allocatePayoutOffsets", () => {
  it("applies post-transfer refund debits oldest first without creating a negative transfer", () => {
    expect(
      allocatePayoutOffsets(2_000, [
        { id: 11, remainingMinor: 1_500 },
        { id: 12, remainingMinor: 1_000 },
      ]),
    ).toEqual({
      appliedMinor: 2_000,
      netPayoutMinor: 0,
      applications: [
        { adjustmentId: 11, amountMinor: 1_500 },
        { adjustmentId: 12, amountMinor: 500 },
      ],
    });
  });

  it("leaves the unconsumed payout available for PayTR transfer", () => {
    expect(
      allocatePayoutOffsets(2_000, [{ id: 11, remainingMinor: 750 }]),
    ).toEqual({
      appliedMinor: 750,
      netPayoutMinor: 1_250,
      applications: [{ adjustmentId: 11, amountMinor: 750 }],
    });
  });
});

describe("calculatePayoutAfterRefunds", () => {
  it("applies pre-delivery refunds to every payout component", () => {
    expect(
      calculatePayoutAfterRefunds({
        grossMinor: 11_500,
        commissionMinor: 1_000,
        commissionVatMinor: 200,
        withholdingMinor: 88,
        venuePayoutMinor: 10_212,
        refunds: [
          {
            amountMinor: 2_500,
            commissionReversalMinor: 250,
            commissionVatReversalMinor: 50,
            withholdingReversalMinor: 22,
          },
        ],
      }),
    ).toEqual({
      grossMinor: 9_000,
      commissionMinor: 750,
      commissionVatMinor: 150,
      withholdingMinor: 66,
      venuePayoutMinor: 8_034,
      refundAdjustmentMinor: -2_178,
    });
  });

  it("rejects refund reversals that exceed the original settlement", () => {
    expect(() =>
      calculatePayoutAfterRefunds({
        grossMinor: 1_000,
        commissionMinor: 100,
        commissionVatMinor: 20,
        withholdingMinor: 10,
        venuePayoutMinor: 870,
        refunds: [
          {
            amountMinor: 1_001,
            commissionReversalMinor: 100,
            commissionVatReversalMinor: 20,
            withholdingReversalMinor: 10,
          },
        ],
      }),
    ).toThrow("Refunds exceed the original settlement");
  });
});
