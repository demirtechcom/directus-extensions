export interface VatBreakdownLine {
  grossMinor: number;
  vatRateBps: number;
}

export interface MarketplaceSettlementInput {
  foodSubtotalMinor: number;
  deliveryFeeMinor: number;
  commissionRateBps: number;
  commissionVatRateBps: number;
  withholdingRateBps: number;
  vatBreakdown: readonly VatBreakdownLine[];
}

export interface MarketplaceSettlement {
  grossMinor: number;
  commissionMinor: number;
  commissionVatMinor: number;
  foodVatMinor: number;
  withholdingMinor: number;
  venuePayoutMinor: number;
}

export function calculateMarketplaceSettlement(
  input: MarketplaceSettlementInput,
): MarketplaceSettlement {
  assertMinor("foodSubtotalMinor", input.foodSubtotalMinor);
  assertMinor("deliveryFeeMinor", input.deliveryFeeMinor);
  assertRate("commissionRateBps", input.commissionRateBps);
  assertRate("commissionVatRateBps", input.commissionVatRateBps);
  assertRate("withholdingRateBps", input.withholdingRateBps);

  const vatGrossMinor = input.vatBreakdown.reduce((total, line) => {
    assertMinor("vatBreakdown.grossMinor", line.grossMinor);
    assertRate("vatBreakdown.vatRateBps", line.vatRateBps);
    return total + line.grossMinor;
  }, 0);
  if (vatGrossMinor !== input.foodSubtotalMinor) {
    throw new Error("VAT breakdown must equal food subtotal");
  }

  const foodVatMinor = input.vatBreakdown.reduce(
    (total, line) =>
      total + Math.round((line.grossMinor * line.vatRateBps) / (10_000 + line.vatRateBps)),
    0,
  );
  const commissionMinor = applyRate(input.foodSubtotalMinor, input.commissionRateBps);
  const commissionVatMinor = applyRate(commissionMinor, input.commissionVatRateBps);
  const foodNetMinor = input.foodSubtotalMinor - foodVatMinor;
  const withholdingMinor = applyRate(foodNetMinor, input.withholdingRateBps);
  const grossMinor = input.foodSubtotalMinor + input.deliveryFeeMinor;

  return {
    grossMinor,
    commissionMinor,
    commissionVatMinor,
    foodVatMinor,
    withholdingMinor,
    venuePayoutMinor: grossMinor - commissionMinor - commissionVatMinor - withholdingMinor,
  };
}

export interface PartialRefundInput {
  refundFoodMinor: number;
  refundDeliveryMinor: number;
  originalFoodMinor: number;
  originalCommissionMinor: number;
  originalCommissionVatMinor: number;
  originalWithholdingMinor: number;
  previousRefundFoodMinor?: number;
  previousCommissionReversalMinor?: number;
  previousCommissionVatReversalMinor?: number;
  previousWithholdingReversalMinor?: number;
}

export interface PartialRefundAllocation {
  refundTotalMinor: number;
  commissionReversalMinor: number;
  commissionVatReversalMinor: number;
  withholdingReversalMinor: number;
  venueDebitMinor: number;
}

export function allocatePartialRefund(input: PartialRefundInput): PartialRefundAllocation {
  assertMinor("refundFoodMinor", input.refundFoodMinor);
  assertMinor("refundDeliveryMinor", input.refundDeliveryMinor);
  assertMinor("originalFoodMinor", input.originalFoodMinor);
  assertMinor("originalCommissionMinor", input.originalCommissionMinor);
  assertMinor("originalCommissionVatMinor", input.originalCommissionVatMinor);
  assertMinor("originalWithholdingMinor", input.originalWithholdingMinor);
  const previousRefundFoodMinor = input.previousRefundFoodMinor ?? 0;
  const previousCommissionReversalMinor = input.previousCommissionReversalMinor ?? 0;
  const previousCommissionVatReversalMinor = input.previousCommissionVatReversalMinor ?? 0;
  const previousWithholdingReversalMinor = input.previousWithholdingReversalMinor ?? 0;
  assertMinor("previousRefundFoodMinor", previousRefundFoodMinor);
  assertMinor("previousCommissionReversalMinor", previousCommissionReversalMinor);
  assertMinor("previousCommissionVatReversalMinor", previousCommissionVatReversalMinor);
  assertMinor("previousWithholdingReversalMinor", previousWithholdingReversalMinor);
  if (previousRefundFoodMinor + input.refundFoodMinor > input.originalFoodMinor) {
    throw new Error("Food refund cannot exceed original food subtotal");
  }
  if (
    previousCommissionReversalMinor > input.originalCommissionMinor ||
    previousCommissionVatReversalMinor > input.originalCommissionVatMinor ||
    previousWithholdingReversalMinor > input.originalWithholdingMinor
  ) {
    throw new Error("Previous fee reversals exceed the original settlement");
  }

  const cumulativeFoodMinor = previousRefundFoodMinor + input.refundFoodMinor;
  const ratio = input.originalFoodMinor === 0 ? 0 : cumulativeFoodMinor / input.originalFoodMinor;
  const commissionReversalMinor =
    Math.round(input.originalCommissionMinor * ratio) - previousCommissionReversalMinor;
  const commissionVatReversalMinor =
    Math.round(input.originalCommissionVatMinor * ratio) - previousCommissionVatReversalMinor;
  const withholdingReversalMinor =
    Math.round(input.originalWithholdingMinor * ratio) - previousWithholdingReversalMinor;
  if (
    commissionReversalMinor < 0 ||
    commissionVatReversalMinor < 0 ||
    withholdingReversalMinor < 0
  ) {
    throw new Error("Previous fee reversals are inconsistent with the refunded food total");
  }
  const refundTotalMinor = input.refundFoodMinor + input.refundDeliveryMinor;

  return {
    refundTotalMinor,
    commissionReversalMinor,
    commissionVatReversalMinor,
    withholdingReversalMinor,
    venueDebitMinor:
      refundTotalMinor -
      commissionReversalMinor -
      commissionVatReversalMinor -
      withholdingReversalMinor,
  };
}

export function calculateRefundLineAmount(input: {
  purchasedQuantity: number;
  previouslyClaimedQuantity: number;
  requestedQuantity: number;
  unitPriceMinor: number;
}): number {
  assertMinor("unitPriceMinor", input.unitPriceMinor);
  for (const [name, value] of [
    ["purchasedQuantity", input.purchasedQuantity],
    ["previouslyClaimedQuantity", input.previouslyClaimedQuantity],
    ["requestedQuantity", input.requestedQuantity],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${name} must be a non-negative safe integer`);
    }
  }
  if (input.requestedQuantity <= 0) {
    throw new Error("requestedQuantity must be positive");
  }
  if (input.previouslyClaimedQuantity + input.requestedQuantity > input.purchasedQuantity) {
    throw new Error("Refund item quantity exceeds the remaining quantity");
  }
  return input.requestedQuantity * input.unitPriceMinor;
}

export interface RefundSettlementAdjustment {
  amountMinor: number;
  commissionReversalMinor: number;
  commissionVatReversalMinor: number;
  withholdingReversalMinor: number;
}

export function calculatePayoutAfterRefunds(input: {
  grossMinor: number;
  commissionMinor: number;
  commissionVatMinor: number;
  withholdingMinor: number;
  venuePayoutMinor: number;
  refunds: readonly RefundSettlementAdjustment[];
}): {
  grossMinor: number;
  commissionMinor: number;
  commissionVatMinor: number;
  withholdingMinor: number;
  venuePayoutMinor: number;
  refundAdjustmentMinor: number;
} {
  assertMinor("grossMinor", input.grossMinor);
  assertMinor("commissionMinor", input.commissionMinor);
  assertMinor("commissionVatMinor", input.commissionVatMinor);
  assertMinor("withholdingMinor", input.withholdingMinor);
  assertMinor("venuePayoutMinor", input.venuePayoutMinor);

  const totals = input.refunds.reduce(
    (sum, refund) => {
      assertMinor("refund.amountMinor", refund.amountMinor);
      assertMinor("refund.commissionReversalMinor", refund.commissionReversalMinor);
      assertMinor("refund.commissionVatReversalMinor", refund.commissionVatReversalMinor);
      assertMinor("refund.withholdingReversalMinor", refund.withholdingReversalMinor);
      const venueDebitMinor =
        refund.amountMinor -
        refund.commissionReversalMinor -
        refund.commissionVatReversalMinor -
        refund.withholdingReversalMinor;
      if (venueDebitMinor < 0) throw new Error("Refunds exceed the original settlement");
      return {
        amountMinor: sum.amountMinor + refund.amountMinor,
        commissionReversalMinor:
          sum.commissionReversalMinor + refund.commissionReversalMinor,
        commissionVatReversalMinor:
          sum.commissionVatReversalMinor + refund.commissionVatReversalMinor,
        withholdingReversalMinor:
          sum.withholdingReversalMinor + refund.withholdingReversalMinor,
        venueDebitMinor: sum.venueDebitMinor + venueDebitMinor,
      };
    },
    {
      amountMinor: 0,
      commissionReversalMinor: 0,
      commissionVatReversalMinor: 0,
      withholdingReversalMinor: 0,
      venueDebitMinor: 0,
    },
  );
  if (
    totals.amountMinor > input.grossMinor ||
    totals.commissionReversalMinor > input.commissionMinor ||
    totals.commissionVatReversalMinor > input.commissionVatMinor ||
    totals.withholdingReversalMinor > input.withholdingMinor ||
    totals.venueDebitMinor > input.venuePayoutMinor
  ) {
    throw new Error("Refunds exceed the original settlement");
  }

  return {
    grossMinor: input.grossMinor - totals.amountMinor,
    commissionMinor: input.commissionMinor - totals.commissionReversalMinor,
    commissionVatMinor: input.commissionVatMinor - totals.commissionVatReversalMinor,
    withholdingMinor: input.withholdingMinor - totals.withholdingReversalMinor,
    venuePayoutMinor: input.venuePayoutMinor - totals.venueDebitMinor,
    refundAdjustmentMinor: -totals.venueDebitMinor,
  };
}

export interface PendingPayoutOffset {
  id: number;
  remainingMinor: number;
}

export interface PayoutOffsetAllocation {
  appliedMinor: number;
  netPayoutMinor: number;
  applications: Array<{ adjustmentId: number; amountMinor: number }>;
}

export function allocatePayoutOffsets(
  venuePayoutMinor: number,
  adjustments: readonly PendingPayoutOffset[],
): PayoutOffsetAllocation {
  assertMinor("venuePayoutMinor", venuePayoutMinor);
  let remainingPayout = venuePayoutMinor;
  const applications: Array<{ adjustmentId: number; amountMinor: number }> = [];

  for (const adjustment of adjustments) {
    assertMinor("adjustment.remainingMinor", adjustment.remainingMinor);
    if (!Number.isSafeInteger(adjustment.id) || adjustment.id <= 0) {
      throw new Error("adjustment.id must be a positive safe integer");
    }
    if (remainingPayout === 0) break;
    const amountMinor = Math.min(remainingPayout, adjustment.remainingMinor);
    if (amountMinor === 0) continue;
    applications.push({ adjustmentId: adjustment.id, amountMinor });
    remainingPayout -= amountMinor;
  }

  return {
    appliedMinor: venuePayoutMinor - remainingPayout,
    netPayoutMinor: remainingPayout,
    applications,
  };
}

function assertMinor(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer minor amount`);
  }
}

function assertRate(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 10_000) {
    throw new Error(`${name} must be an integer between 0 and 10000`);
  }
}

function applyRate(amountMinor: number, rateBps: number): number {
  return Math.round((amountMinor * rateBps) / 10_000);
}
