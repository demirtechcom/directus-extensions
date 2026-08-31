import { describe, expect, it } from "bun:test";

import { registerMarketplaceRoutes, type MarketplaceApplication } from "./marketplace-routes";

interface CapturedRoute {
  method: "get" | "post";
  path: string;
  handler: (request: Record<string, unknown>, response: TestResponse) => Promise<unknown>;
}

class TestResponse {
  statusCode = 200;
  body: unknown;

  status(code: number): this {
    this.statusCode = code;
    return this;
  }

  json(body: unknown): this {
    this.body = body;
    return this;
  }

  send(body: unknown): this {
    this.body = body;
    return this;
  }
}

function setup(applicationOverrides: Partial<MarketplaceApplication> = {}) {
  const routes: CapturedRoute[] = [];
  const router = {
    get(path: string, handler: CapturedRoute["handler"]): void {
      routes.push({ method: "get", path, handler });
    },
    post(path: string, handler: CapturedRoute["handler"]): void {
      routes.push({ method: "post", path, handler });
    },
  };
  const application: MarketplaceApplication = {
    createPaymentAttempt: async () => ({
      token: "iframe-token",
      merchant_oid: "KYO42A7",
      expires_at: "2026-08-31T10:15:00.000Z",
    }),
    getPaymentStatus: async () => ({
      order_status: "awaiting_payment",
      payment_status: "pending",
    }),
    handlePaytrCallback: async () => undefined,
    acceptOrder: async () => ({ order_status: "preparing" }),
    cancelOrder: async () => ({ order_status: "cancelled", refund_status: null }),
    refundOrder: async () => ({ refund_status: "succeeded" }),
    verifyDelivery: async () => ({ order_status: "delivered" }),
    submitPayout: async () => ({ payout_status: "submitted" }),
    updatePaymentAccount: async () => ({ activation_status: "under_review" }),
    reviewPaymentAccount: async () => ({ activation_status: "approved" }),
    runLifecycle: async () => ({ reconciled: 0, refunded: 0, submitted: 0 }),
    ...applicationOverrides,
  };

  registerMarketplaceRoutes(router as never, application);
  return { routes };
}

describe("registerMarketplaceRoutes", () => {
  it("registers the marketplace command and query contract", () => {
    const { routes } = setup();

    expect(routes.map(({ method, path }) => `${method.toUpperCase()} ${path}`)).toEqual([
      "POST /orders/:id/payment-attempts",
      "GET /orders/:id/payment-status",
      "POST /paytr/callback",
      "POST /orders/:id/accept",
      "POST /orders/:id/cancel",
      "POST /orders/:id/refunds",
      "POST /orders/:id/delivery-verification",
      "POST /payouts/:id/transfers",
      "POST /venues/:id/payment-account",
      "POST /venues/:id/payment-account/review",
    ]);
  });

  it("requires authentication for customer payment attempts", async () => {
    const { routes } = setup();
    const route = routes.find((item) => item.path === "/orders/:id/payment-attempts");
    const response = new TestResponse();

    await route?.handler({ params: { id: "42" }, body: {} }, response);

    expect(response.statusCode).toBe(401);
    expect(response.body).toEqual({ error: { code: "AUTHENTICATION_REQUIRED" } });
  });

  it("always acknowledges a syntactically valid provider callback after processing", async () => {
    let handled = false;
    const { routes } = setup({
      handlePaytrCallback: async () => {
        handled = true;
      },
    });
    const route = routes.find((item) => item.path === "/paytr/callback");
    const response = new TestResponse();

    await route?.handler({ body: { merchant_oid: "KYO42A7" } }, response);

    expect(handled).toBe(true);
    expect(response.body).toBe("OK");
  });
});
