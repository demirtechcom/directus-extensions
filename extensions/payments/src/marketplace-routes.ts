import type { Request, Response, Router } from "express";

export interface MarketplaceApplication {
  createPaymentAttempt(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  getPaymentStatus(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  handlePaytrCallback(input: Record<string, unknown>): Promise<void>;
  acceptOrder(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  cancelOrder(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  refundOrder(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  verifyDelivery(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  submitPayout(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  updatePaymentAccount(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  reviewPaymentAccount(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  runLifecycle(input: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export class MarketplaceApplicationError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "MarketplaceApplicationError";
  }
}

type AuthenticatedRequest = Request & {
  accountability?: { user?: string | null };
};

export function registerMarketplaceRoutes(
  router: Router,
  application: MarketplaceApplication,
): void {
  router.post("/orders/:id/payment-attempts", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedOrderCommand(req, res, application.createPaymentAttempt);
  });
  router.get("/orders/:id/payment-status", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedOrderCommand(req, res, application.getPaymentStatus);
  });
  router.post("/paytr/callback", async (req: Request, res: Response) => {
    try {
      await application.handlePaytrCallback(recordBody(req.body));
      res.send("OK");
    } catch (error: unknown) {
      sendError(res, error);
    }
  });
  router.post("/orders/:id/accept", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedOrderCommand(req, res, application.acceptOrder);
  });
  router.post("/orders/:id/cancel", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedOrderCommand(req, res, application.cancelOrder);
  });
  router.post("/orders/:id/refunds", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedOrderCommand(req, res, application.refundOrder);
  });
  router.post(
    "/orders/:id/delivery-verification",
    async (req: AuthenticatedRequest, res: Response) => {
      await authenticatedOrderCommand(req, res, application.verifyDelivery);
    },
  );
  router.post("/payouts/:id/transfers", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedCommand(req, res, "payoutId", application.submitPayout);
  });
  router.post("/venues/:id/payment-account", async (req: AuthenticatedRequest, res: Response) => {
    await authenticatedCommand(req, res, "venueId", application.updatePaymentAccount);
  });
  router.post(
    "/venues/:id/payment-account/review",
    async (req: AuthenticatedRequest, res: Response) => {
      await authenticatedCommand(req, res, "venueId", application.reviewPaymentAccount);
    },
  );
}

async function authenticatedOrderCommand(
  req: AuthenticatedRequest,
  res: Response,
  command: (input: Record<string, unknown>) => Promise<Record<string, unknown>>,
): Promise<void> {
  await authenticatedCommand(req, res, "orderId", command);
}

async function authenticatedCommand(
  req: AuthenticatedRequest,
  res: Response,
  idField: "orderId" | "payoutId" | "venueId",
  command: (input: Record<string, unknown>) => Promise<Record<string, unknown>>,
): Promise<void> {
  const userId = req.accountability?.user;
  if (!userId) {
    res.status(401).json({ error: { code: "AUTHENTICATION_REQUIRED" } });
    return;
  }
  const orderId = Number(req.params.id);
  if (!Number.isSafeInteger(orderId) || orderId <= 0) {
    res.status(400).json({ error: { code: "INVALID_ORDER_ID" } });
    return;
  }

  try {
    const result = await command({
      [idField]: orderId,
      userId,
      userIp: clientIp(req),
      ...recordBody(req.body),
    });
    res.json(result);
  } catch (error: unknown) {
    sendError(res, error);
  }
}

function recordBody(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function clientIp(req: Request): string {
  const forwarded = req.headers?.["x-forwarded-for"];
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  return String(raw ?? req.headers?.["x-real-ip"] ?? req.ip ?? "127.0.0.1")
    .split(",")[0]
    .trim();
}

function sendError(res: Response, error: unknown): void {
  if (error instanceof MarketplaceApplicationError) {
    res.status(error.status).json({ error: { code: error.code } });
    return;
  }
  res.status(500).json({ error: { code: "MARKETPLACE_PAYMENT_FAILED" } });
}
