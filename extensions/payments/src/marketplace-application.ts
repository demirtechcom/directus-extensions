import { createHash } from "node:crypto";

import {
  allocatePartialRefund,
  allocatePayoutOffsets,
  calculatePayoutAfterRefunds,
  calculateRefundLineAmount,
} from "./marketplace-finance.js";
import {
  acceptanceTimeoutRefundIdempotencyKey,
  applyVerifiedPaymentCallback,
  canOpenPaymentAttempt,
  canRevealDeliveryCode,
  createMerchantOid,
  deriveDeliveryCode,
  hashDeliveryCode,
  payoutRequiresBalanceAdjustment,
  providerCommandFailureDisposition,
  verifyDeliveryCode,
} from "./marketplace-order.js";
import {
  MarketplaceApplicationError,
  type MarketplaceApplication,
} from "./marketplace-routes.js";
import { decryptIban, encryptIban } from "./payment-account-crypto.js";
import {
  normalizePaytrCurrency,
  PaytrMarketplaceClient,
  PaytrProviderError,
  type PaytrPaymentStatus,
} from "./paytr-client.js";
import {
  verifyPaytrCallback,
  type PaytrCredentials,
} from "./paytr-marketplace.js";

type Row = Record<string, unknown>;

interface QueryOptions {
  filter?: Row;
  fields?: Array<string | Row>;
  limit?: number;
  sort?: string[];
}

interface ItemsServiceLike {
  readByQuery(options: QueryOptions): Promise<Row[]>;
  readOne(key: string | number, options?: QueryOptions): Promise<Row>;
  createOne(payload: Row): Promise<unknown>;
  updateOne(key: string | number, payload: Row): Promise<unknown>;
}

interface UsersServiceLike {
  readOne(key: string, options?: QueryOptions): Promise<Row>;
}

interface QueryBuilder {
  where(filter: Row): QueryBuilder;
  whereIn(field: string, values: unknown[]): QueryBuilder;
  forUpdate(): QueryBuilder;
  first(...fields: string[]): Promise<Row | undefined>;
  update(payload: Row): Promise<number>;
}

interface DatabaseTransaction {
  (table: string): QueryBuilder;
}

interface ServiceOptions {
  schema: unknown;
  knex?: DatabaseTransaction;
  accountability: { admin: true };
}

interface MarketplaceContext {
  env: Record<string, unknown>;
  services: {
    ItemsService: new (collection: string, options: ServiceOptions) => ItemsServiceLike;
    UsersService: new (options: ServiceOptions) => UsersServiceLike;
  };
  getSchema(): Promise<unknown>;
  database: {
    transaction<T>(handler: (trx: DatabaseTransaction) => Promise<T>): Promise<T>;
  };
  logger: {
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
}

interface Actor {
  id: string;
  email: string;
  name: string;
  phone: string;
  venueId: number | null;
  isAdmin: boolean;
}

interface OrderContext {
  order: Row;
  payment: Row;
  attempts: Row[];
}

interface RefundRequest {
  orderId: number;
  actorId: string | null;
  refundType:
    | "full"
    | "partial"
    | "excess_capture"
    | "acceptance_timeout"
    | "customer_cancel"
    | "chargeback";
  reason: string;
  idempotencyKey: string;
  amountMinor?: number;
  itemRequests?: Array<{ orderItemId: number; quantity: number }>;
  includeDeliveryFee?: boolean;
  attemptId?: number;
}

const PAYMENT_WINDOW_MS = 15 * 60 * 1_000;
const ACCEPTANCE_WINDOW_MS = 5 * 60 * 1_000;
const DELIVERY_LOCK_MS = 15 * 60 * 1_000;
const DELIVERY_FAILURE_LIMIT = 5;

export function createMarketplaceApplication(context: MarketplaceContext): MarketplaceApplication {
  let client: PaytrMarketplaceClient | null = null;

  function provider(): PaytrMarketplaceClient {
    client ??= new PaytrMarketplaceClient(credentials(context.env));
    return client;
  }

  const application: MarketplaceApplication = {
    createPaymentAttempt: async (input) => {
      const orderId = positiveInteger(input.orderId, "orderId");
      const userId = requiredString(input.userId, "userId");
      const userIp = requiredString(input.userIp, "userIp");
      const idempotencyKey = commandKey(input.idempotency_key);
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      let orderContext = await readOrderContext(schema, orderId);
      assertCustomerOwnsOrder(orderContext.order, actor);
      if (!["awaiting_payment", "expired"].includes(stringField(orderContext.order, "order_status"))) {
        throw appError(409, "ORDER_NOT_AWAITING_PAYMENT", "Order is not awaiting payment");
      }

      const repeatedAttempt = orderContext.attempts.find(
        (attempt) => attempt.request_idempotency_key === idempotencyKey,
      );
      if (repeatedAttempt) {
        if (repeatedAttempt.attempt_status !== "pending") {
          throw appError(409, "PAYMENT_ATTEMPT_FINALIZED", "Payment attempt is already finalized");
        }
        return requestIframeToken(schema, orderContext, repeatedAttempt, actor, userIp);
      }

      const latest = orderContext.attempts.at(-1);
      if (latest) {
        const reconciled = await reconcileAttempt(schema, orderContext, latest);
        if (reconciled === "captured") {
          throw appError(409, "PAYMENT_ALREADY_COMPLETED", "Payment was already completed");
        }
        orderContext = await readOrderContext(schema, orderId);
        const currentLatest = orderContext.attempts.at(-1);
        if (currentLatest && !canOpenPaymentAttempt([{ status: attemptStatus(currentLatest) }])) {
          throw appError(409, "PAYMENT_ATTEMPT_PENDING", "Previous payment attempt is still pending");
        }
      }

      await writeAudit(schema, {
        idempotencyKey,
        action: "order_payment",
        outcome: "started",
        actorId: userId,
        orderId,
      });

      const expiresAt = new Date(Date.now() + PAYMENT_WINDOW_MS).toISOString();
      const attempt = await context.database.transaction(async (trx) => {
        const lockedOrder = await trx("orders").where({ id: orderId }).forUpdate().first("*");
        if (!lockedOrder || !["awaiting_payment", "expired"].includes(String(lockedOrder.order_status))) {
          throw appError(409, "ORDER_NOT_AWAITING_PAYMENT", "Order changed while payment started");
        }
        const Attempts = items("order_payment_attempts", schema, trx);
        const existing = await Attempts.readByQuery({
          filter: { request_idempotency_key: { _eq: idempotencyKey } },
          fields: ["*"],
          limit: 1,
        });
        if (existing[0]) return existing[0];
        const openAttempts = await Attempts.readByQuery({
          filter: {
            _and: [
              { order_id: { _eq: orderId } },
              { attempt_status: { _eq: "pending" } },
            ],
          },
          fields: ["id"],
          limit: 1,
        });
        if (openAttempts[0]) {
          throw appError(
            409,
            "PAYMENT_ATTEMPT_PENDING",
            "Another payment attempt is already pending",
          );
        }

        const attemptId = numericId(
          await Attempts.createOne({
            payment_id: numericId(orderContext.payment.id, "payment.id"),
            order_id: orderId,
            request_idempotency_key: idempotencyKey,
            merchant_oid: null,
            attempt_status: "pending",
            amount_minor: positiveInteger(orderContext.payment.amount_minor, "payment.amount_minor"),
            currency: stringField(orderContext.payment, "currency"),
            expires_at: expiresAt,
          }),
          "attempt.id",
        );
        const merchantOid = createMerchantOid(orderId, attemptId);
        await Attempts.updateOne(attemptId, { merchant_oid: merchantOid });
        await items("online_order_payments", schema, trx).updateOne(
          numericId(orderContext.payment.id, "payment.id"),
          { payment_status: "pending" },
        );
        await items("orders", schema, trx).updateOne(orderId, {
          order_status: "awaiting_payment",
          payment_expires_at: expiresAt,
        });
        return {
          id: attemptId,
          payment_id: orderContext.payment.id,
          order_id: orderId,
          request_idempotency_key: idempotencyKey,
          merchant_oid: merchantOid,
          attempt_status: "pending",
          amount_minor: orderContext.payment.amount_minor,
          currency: orderContext.payment.currency,
          expires_at: expiresAt,
        };
      });

      orderContext = { ...orderContext, attempts: [...orderContext.attempts, attempt] };
      try {
        const response = await requestIframeToken(schema, orderContext, attempt, actor, userIp);
        await writeAudit(schema, {
          idempotencyKey,
          action: "order_payment",
          outcome: "completed",
          actorId: userId,
          orderId,
          paymentId: numericId(orderContext.payment.id, "payment.id"),
        });
        return response;
      } catch (error: unknown) {
        await items("order_payment_attempts", schema).updateOne(
          numericId(attempt.id, "attempt.id"),
          {
            attempt_status: "failed",
            failure_code: "IFRAME_TOKEN_FAILED",
            failure_message: safeError(error),
          },
        );
        await items("online_order_payments", schema).updateOne(
          numericId(orderContext.payment.id, "payment.id"),
          { payment_status: "failed" },
        );
        await writeAudit(schema, {
          idempotencyKey,
          action: "order_payment",
          outcome: "failed",
          actorId: userId,
          orderId,
          paymentId: numericId(orderContext.payment.id, "payment.id"),
        });
        throw error;
      }
    },

    getPaymentStatus: async (input) => {
      const orderId = positiveInteger(input.orderId, "orderId");
      const userId = requiredString(input.userId, "userId");
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      let orderContext = await readOrderContext(schema, orderId);
      assertCustomerOwnsOrder(orderContext.order, actor);

      const latest = orderContext.attempts.at(-1);
      if (latest?.attempt_status === "pending" && Date.now() >= Date.parse(stringField(latest, "expires_at"))) {
        await reconcileAttempt(schema, orderContext, latest);
        orderContext = await readOrderContext(schema, orderId);
      }
      await expireAcceptanceIfNeeded(schema, orderContext);
      orderContext = await readOrderContext(schema, orderId);

      const orderStatus = stringField(orderContext.order, "order_status");
      const paymentStatus = stringField(orderContext.payment, "payment_status");
      const response: Row = {
        order_status: orderStatus,
        payment_status: paymentStatus,
        amount_minor: orderContext.payment.amount_minor,
        currency: orderContext.payment.currency,
        acceptance_deadline_at: orderContext.payment.acceptance_deadline_at ?? null,
        retry_allowed:
          ["awaiting_payment", "expired"].includes(orderStatus) &&
          (!orderContext.attempts.at(-1) ||
            ["failed", "expired"].includes(attemptStatus(orderContext.attempts.at(-1) as Row))),
      };
      if (canRevealDeliveryCode(paymentStatus, orderStatus)) {
        response.delivery_code = deriveDeliveryCode(orderId, deliveryPepper(context.env));
      }
      return response;
    },

    handlePaytrCallback: async (input) => {
      const merchantOid = requiredString(input.merchant_oid, "merchant_oid");
      const status = callbackStatus(input.status);
      const totalAmountMinor = positiveInteger(Number(input.total_amount), "total_amount");
      const hash = requiredString(input.hash, "hash");
      const callbackCurrency =
        status === "success" ? normalizePaytrCurrency(input.currency) : null;
      const config = credentials(context.env);
      if (!verifyPaytrCallback(config, { merchantOid, status, totalAmountMinor, hash })) {
        throw appError(400, "INVALID_PAYTR_SIGNATURE", "PayTR callback signature is invalid");
      }

      const schema = await context.getSchema();
      const Attempts = items("order_payment_attempts", schema);
      const attempts = await Attempts.readByQuery({
        filter: { merchant_oid: { _eq: merchantOid } },
        fields: ["*"],
        limit: 1,
      });
      const attempt = attempts[0];
      if (!attempt) throw appError(404, "PAYMENT_ATTEMPT_NOT_FOUND", "Payment attempt was not found");
      const eventKey = sha256(`callback:${merchantOid}:${status}:${totalAmountMinor}:${hash}`);
      if (await providerEventExists(schema, eventKey)) return;

      let verifiedStatus: PaytrPaymentStatus | null = null;
      if (status === "success") {
        verifiedStatus = await provider().queryStatus(merchantOid);
        if (
          !verifiedStatus.captured ||
          verifiedStatus.amountMinor !== totalAmountMinor ||
          verifiedStatus.currency !== callbackCurrency
        ) {
          throw appError(
            409,
            "PAYTR_STATUS_MISMATCH",
            "PayTR status query did not confirm callback amount and currency",
          );
        }
      }

      const result = await applyProviderResult(schema, {
        attempt,
        status,
        amountMinor: totalAmountMinor,
        currency: callbackCurrency ?? stringField(attempt, "currency"),
        paymentType: verifiedStatus?.paymentType ?? optionalString(input.payment_type),
        eventKey,
        eventType: "callback",
        payloadHash: sha256(JSON.stringify(redactedCallback(input))),
      });
      if (result.refundExcessAttempt) {
        await performRefund(schema, {
          orderId: numericId(attempt.order_id, "attempt.order_id"),
          actorId: null,
          refundType: "excess_capture",
          reason: "Automatic refund for duplicate capture",
          idempotencyKey: `excess-${numericId(attempt.id, "attempt.id")}`,
          amountMinor: totalAmountMinor,
          attemptId: numericId(attempt.id, "attempt.id"),
        });
      }
    },

    acceptOrder: async (input) => {
      const orderId = positiveInteger(input.orderId, "orderId");
      const userId = requiredString(input.userId, "userId");
      const idempotencyKey = commandKey(input.idempotency_key);
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      const orderContext = await readOrderContext(schema, orderId, true);
      assertVenueCanManage(orderContext.order, actor);
      const deadline = optionalString(orderContext.payment.acceptance_deadline_at);
      if (deadline && Date.now() >= Date.parse(deadline)) {
        await cancelForAcceptanceTimeout(schema, orderContext);
        throw appError(409, "ACCEPTANCE_WINDOW_EXPIRED", "Restaurant acceptance window expired");
      }

      await writeAudit(schema, {
        idempotencyKey,
        action: "order_acceptance",
        outcome: "started",
        actorId: userId,
        orderId,
      });
      const updated = await context.database.transaction(async (trx) =>
        trx("orders").where({ id: orderId, order_status: "pending" }).update({
          order_status: "preparing",
        }),
      );
      if (updated !== 1) {
        throw appError(409, "ORDER_STATE_CONFLICT", "Order was already changed");
      }
      await writeAudit(schema, {
        idempotencyKey,
        action: "order_acceptance",
        outcome: "completed",
        actorId: userId,
        orderId,
      });
      return { order_status: "preparing" };
    },

    cancelOrder: async (input) => {
      const orderId = positiveInteger(input.orderId, "orderId");
      const userId = requiredString(input.userId, "userId");
      const idempotencyKey = commandKey(input.idempotency_key);
      const reason = optionalString(input.reason) ?? "Customer cancelled before preparation";
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      const orderContext = await readOrderContext(schema, orderId, false);
      const customerOwnsOrder = relatedStringId(orderContext.order.user_id) === actor.id;
      if (!customerOwnsOrder) assertVenueCanManage(orderContext.order, actor);
      if (orderContext.order.order_status === "cancelled") {
        return { order_status: "cancelled", refund_status: "succeeded" };
      }

      await writeAudit(schema, {
        idempotencyKey,
        action: "order_cancel",
        outcome: "started",
        actorId: userId,
        orderId,
      });
      const updated = await context.database.transaction(async (trx) =>
        trx("orders")
          .where({ id: orderId })
          .whereIn("order_status", ["awaiting_payment", "pending"])
          .update({ order_status: "cancelled", cancellation_reason: reason }),
      );
      if (updated !== 1) {
        throw appError(409, "ORDER_CANNOT_BE_CANCELLED", "Order is already being prepared");
      }

      let refundStatus: string | null = null;
      if (["succeeded", "partially_refunded"].includes(stringField(orderContext.payment, "payment_status"))) {
        const remaining =
          positiveInteger(orderContext.payment.amount_minor, "payment.amount_minor") -
          nonNegativeInteger(orderContext.payment.refunded_amount_minor, "payment.refunded_amount_minor");
        if (remaining > 0) {
          const refund = await performRefund(schema, {
            orderId,
            actorId: userId,
            refundType: customerOwnsOrder ? "customer_cancel" : "full",
            reason,
            idempotencyKey: `${idempotencyKey}-refund`,
            amountMinor: remaining,
            includeDeliveryFee: true,
          });
          refundStatus = stringField(refund, "refund_status");
        }
      }
      await writeAudit(schema, {
        idempotencyKey,
        action: "order_cancel",
        outcome: "completed",
        actorId: userId,
        orderId,
      });
      return { order_status: "cancelled", refund_status: refundStatus };
    },

    refundOrder: async (input) => {
      const orderId = positiveInteger(input.orderId, "orderId");
      const userId = requiredString(input.userId, "userId");
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      if (!actor.isAdmin) throw appError(403, "ADMIN_REQUIRED", "Administrator access is required");
      const itemRequests = parseRefundItems(input.items);
      const amountMinor = input.amount_minor == null ? undefined : positiveInteger(input.amount_minor, "amount_minor");
      if (!amountMinor && itemRequests.length === 0 && input.include_delivery_fee !== true) {
        throw appError(400, "REFUND_AMOUNT_REQUIRED", "Refund amount or items are required");
      }
      const refund = await performRefund(schema, {
        orderId,
        actorId: userId,
        refundType: amountMinor ? "partial" : "partial",
        reason: requiredString(input.reason, "reason"),
        idempotencyKey: commandKey(input.idempotency_key),
        amountMinor,
        itemRequests,
        includeDeliveryFee: input.include_delivery_fee === true,
      });
      return {
        refund_id: refund.id,
        refund_status: refund.refund_status,
        amount_minor: refund.amount_minor,
      };
    },

    verifyDelivery: async (input) => {
      const orderId = positiveInteger(input.orderId, "orderId");
      const userId = requiredString(input.userId, "userId");
      const code = requiredString(input.code, "code");
      const idempotencyKey = commandKey(input.idempotency_key);
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      const orderContext = await readOrderContext(schema, orderId, true);
      assertVenueCanManage(orderContext.order, actor);

      const outcome = await context.database.transaction(async (trx) => {
        const order = await trx("orders").where({ id: orderId }).forUpdate().first("*");
        if (!order || order.order_status !== "preparing") {
          throw appError(409, "ORDER_NOT_PREPARING", "Order is not ready for delivery verification");
        }
        const Verifications = items("order_delivery_verifications", schema, trx);
        const rows = await Verifications.readByQuery({
          filter: { order_id: { _eq: orderId } },
          fields: ["*"],
          limit: 1,
        });
        const verification = rows[0];
        if (!verification) {
          throw appError(409, "DELIVERY_CODE_NOT_READY", "Delivery code has not been issued");
        }
        const lockedUntil = optionalString(verification.locked_until);
        if (lockedUntil && Date.now() < Date.parse(lockedUntil)) {
          throw appError(429, "DELIVERY_CODE_RATE_LIMITED", "Too many delivery-code attempts");
        }
        const valid = verifyDeliveryCode(
          orderId,
          code,
          deliveryPepper(context.env),
          stringField(verification, "code_hash"),
        );
        if (!valid) {
          const failures = nonNegativeInteger(verification.failed_attempts, "failed_attempts") + 1;
          await Verifications.updateOne(numericId(verification.id, "verification.id"), {
            failed_attempts: failures,
            last_attempt_at: new Date().toISOString(),
            locked_until:
              failures % DELIVERY_FAILURE_LIMIT === 0
                ? new Date(Date.now() + DELIVERY_LOCK_MS).toISOString()
                : null,
          });
          return "invalid" as const;
        }

        const now = new Date().toISOString();
        const payment = await trx("online_order_payments")
          .where({ id: numericId(orderContext.payment.id, "payment.id") })
          .forUpdate()
          .first("*");
        if (!payment) throw appError(404, "PAYMENT_NOT_FOUND", "Online payment was not found");
        await Verifications.updateOne(numericId(verification.id, "verification.id"), {
          verified_at: now,
          verified_by: userId,
          locked_until: null,
        });
        await items("orders", schema, trx).updateOne(orderId, { order_status: "delivered" });

        if (["succeeded", "partially_refunded", "refunded"].includes(paymentStatus(payment))) {
          const Payouts = items("venue_payouts", schema, trx);
          const existing = await Payouts.readByQuery({
            filter: { order_id: { _eq: orderId } },
            fields: ["id"],
            limit: 1,
          });
          if (!existing[0]) {
            const paidAt = optionalString(payment.paid_at) ?? now;
            const venueId = numericId(orderContext.order.venue_id, "order.venue_id");
            const refunds = await items("order_refunds", schema, trx).readByQuery({
              filter: {
                _and: [
                  { order_id: { _eq: orderId } },
                  { refund_status: { _in: ["processing", "succeeded"] } },
                ],
              },
              fields: [
                "amount_minor",
                "commission_reversal_minor",
                "commission_vat_reversal_minor",
                "withholding_reversal_minor",
              ],
              limit: -1,
            });
            const adjustedPayout = calculatePayoutAfterRefunds({
              grossMinor: positiveInteger(payment.amount_minor, "payment.amount_minor"),
              commissionMinor: nonNegativeInteger(
                payment.commission_minor,
                "payment.commission_minor",
              ),
              commissionVatMinor: nonNegativeInteger(
                payment.commission_vat_minor,
                "payment.commission_vat_minor",
              ),
              withholdingMinor: nonNegativeInteger(
                payment.withholding_minor,
                "payment.withholding_minor",
              ),
              venuePayoutMinor: nonNegativeInteger(
                payment.venue_net_minor,
                "payment.venue_net_minor",
              ),
              refunds: refunds.map((refund) => ({
                amountMinor: positiveInteger(refund.amount_minor, "refund.amount_minor"),
                commissionReversalMinor: nonNegativeInteger(
                  refund.commission_reversal_minor,
                  "refund.commission_reversal_minor",
                ),
                commissionVatReversalMinor: nonNegativeInteger(
                  refund.commission_vat_reversal_minor,
                  "refund.commission_vat_reversal_minor",
                ),
                withholdingReversalMinor: nonNegativeInteger(
                  refund.withholding_reversal_minor,
                  "refund.withholding_reversal_minor",
                ),
              })),
            });
            const Adjustments = items("venue_balance_adjustments", schema, trx);
            const pendingAdjustments = await Adjustments.readByQuery({
              filter: {
                _and: [
                  { venue_id: { _eq: venueId } },
                  { adjustment_status: { _in: ["pending", "partial"] } },
                ],
              },
              fields: ["*"],
              sort: ["date_created", "id"],
              limit: -1,
            });
            const offsets = allocatePayoutOffsets(
              adjustedPayout.venuePayoutMinor,
              pendingAdjustments.map((adjustment) => ({
                id: numericId(adjustment.id, "adjustment.id"),
                remainingMinor:
                  positiveInteger(adjustment.amount_minor, "adjustment.amount_minor") -
                  nonNegativeInteger(
                    adjustment.applied_amount_minor,
                    "adjustment.applied_amount_minor",
                  ),
              })),
            );
            const payoutId = numericId(await Payouts.createOne({
              venue_id: venueId,
              order_id: orderId,
              payment_id: numericId(payment.id, "payment.id"),
              payout_status: offsets.netPayoutMinor === 0 ? "offset" : "scheduled",
              gross_minor: adjustedPayout.grossMinor,
              commission_minor: adjustedPayout.commissionMinor,
              commission_vat_minor: adjustedPayout.commissionVatMinor,
              withholding_minor: adjustedPayout.withholdingMinor,
              refund_adjustment_minor:
                adjustedPayout.refundAdjustmentMinor - offsets.appliedMinor,
              net_minor: offsets.netPayoutMinor,
              currency: payment.currency,
              eligible_on: nextTransferDate(paidAt),
            }), "payout.id");
            const Applications = items("venue_payout_adjustment_applications", schema, trx);
            for (const application of offsets.applications) {
              const adjustment = pendingAdjustments.find(
                (candidate) => Number(candidate.id) === application.adjustmentId,
              );
              if (!adjustment) continue;
              const appliedAmount =
                nonNegativeInteger(
                  adjustment.applied_amount_minor,
                  "adjustment.applied_amount_minor",
                ) + application.amountMinor;
              const totalAmount = positiveInteger(
                adjustment.amount_minor,
                "adjustment.amount_minor",
              );
              await Applications.createOne({
                application_key: `${payoutId}:${application.adjustmentId}`,
                payout_id: payoutId,
                adjustment_id: application.adjustmentId,
                amount_minor: application.amountMinor,
              });
              await Adjustments.updateOne(application.adjustmentId, {
                applied_amount_minor: appliedAmount,
                adjustment_status: appliedAmount >= totalAmount ? "applied" : "partial",
              });
            }
          }
        }
        return "delivered" as const;
      });
      if (outcome === "invalid") {
        await writeAudit(schema, {
          idempotencyKey,
          action: "delivery_verification",
          outcome: "failed",
          actorId: userId,
          orderId,
        });
        throw appError(422, "DELIVERY_CODE_INVALID", "Delivery code is invalid");
      }
      await writeAudit(schema, {
        idempotencyKey,
        action: "delivery_verification",
        outcome: "completed",
        actorId: userId,
        orderId,
      });
      return { order_status: "delivered" };
    },

    submitPayout: async (input) => {
      const payoutId = positiveInteger(input.payoutId, "payoutId");
      const userId = requiredString(input.userId, "userId");
      const idempotencyKey = commandKey(input.idempotency_key);
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      if (!actor.isAdmin) throw appError(403, "ADMIN_REQUIRED", "Administrator access is required");
      const Payouts = items("venue_payouts", schema);
      const payout = await Payouts.readOne(payoutId, { fields: ["*"] });
      if (payout.payout_status === "offset") {
        return { payout_status: "offset", transfer_id: null };
      }
      if (["submitted", "succeeded"].includes(stringField(payout, "payout_status"))) {
        return { payout_status: payout.payout_status, transfer_id: payout.transfer_id };
      }
      if (payout.payout_status === "instruction_pending") {
        throw appError(
          409,
          "PAYOUT_RECONCILIATION_REQUIRED",
          "Transfer outcome must be reconciled before retrying",
        );
      }
      if (stringField(payout, "eligible_on") > new Date().toISOString().slice(0, 10)) {
        throw appError(409, "PAYOUT_NOT_ELIGIBLE", "Payout is not eligible for transfer yet");
      }
      const account = await readOneByFilter(items("venue_payment_accounts", schema), {
        venue_id: { _eq: numericId(payout.venue_id, "payout.venue_id") },
      });
      if (!account || account.activation_status !== "approved") {
        throw appError(409, "PAYMENT_ACCOUNT_NOT_APPROVED", "Restaurant payment account is not approved");
      }
      const payment = await items("online_order_payments", schema).readOne(
        numericId(payout.payment_id, "payout.payment_id"),
        { fields: ["*"] },
      );
      const attempts = await items("order_payment_attempts", schema).readByQuery({
        filter: {
          _and: [
            { payment_id: { _eq: payment.id } },
            { attempt_status: { _eq: "succeeded" } },
          ],
        },
        fields: ["*"],
        sort: ["-id"],
        limit: 1,
      });
      const attempt = attempts[0];
      if (!attempt) throw appError(409, "CAPTURE_NOT_FOUND", "Captured payment attempt was not found");
      const transferId = optionalString(payout.transfer_id) ?? `KYP${payoutId}`;
      const transferIban = decryptIban(
        {
          ciphertext: requiredString(account.transfer_iban_ciphertext, "transfer_iban_ciphertext"),
          iv: requiredString(account.transfer_iban_iv, "transfer_iban_iv"),
          authTag: requiredString(account.transfer_iban_auth_tag, "transfer_iban_auth_tag"),
          masked: optionalString(account.masked_iban) ?? "",
        },
        paymentAccountKey(context.env),
      );
      const terminalPayout = await context.database.transaction(async (trx) => {
        const locked = await trx("venue_payouts").where({ id: payoutId }).forUpdate().first("*");
        if (!locked) throw appError(404, "PAYOUT_NOT_FOUND", "Payout was not found");
        const status = stringField(locked, "payout_status");
        if (["offset", "submitted", "succeeded"].includes(status)) return locked;
        if (status === "instruction_pending") {
          throw appError(
            409,
            "PAYOUT_RECONCILIATION_REQUIRED",
            "Transfer outcome must be reconciled before retrying",
          );
        }
        if (!["scheduled", "failed"].includes(status)) {
          throw appError(409, "PAYOUT_STATE_CONFLICT", "Payout cannot be submitted");
        }
        await items("venue_payouts", schema, trx).updateOne(payoutId, {
          payout_status: "instruction_pending",
          transfer_id: transferId,
          failure_reason: null,
        });
        return null;
      });
      if (terminalPayout) {
        return {
          payout_status: terminalPayout.payout_status,
          transfer_id: terminalPayout.transfer_id ?? null,
        };
      }
      await writeAudit(schema, {
        idempotencyKey,
        action: "payout_transfer",
        outcome: "started",
        actorId: userId,
        orderId: numericId(payout.order_id, "payout.order_id"),
        payoutId,
      });
      let providerAccepted = false;
      try {
        const result = await provider().transfer({
          merchantOid: stringField(attempt, "merchant_oid"),
          transferId,
          submerchantAmountMinor: positiveInteger(payout.net_minor, "payout.net_minor"),
          totalAmountMinor: positiveInteger(payment.amount_minor, "payment.amount_minor"),
          transferName: requiredString(account.legal_name, "legal_name"),
          transferIban,
        });
        providerAccepted = true;
        await Payouts.updateOne(payoutId, {
          payout_status: "submitted",
          transfer_id: transferId,
          provider_status: result.providerStatus,
          submitted_at: new Date().toISOString(),
        });
        await writeAudit(schema, {
          idempotencyKey,
          action: "payout_transfer",
          outcome: "completed",
          actorId: userId,
          orderId: numericId(payout.order_id, "payout.order_id"),
          payoutId,
        });
        return { payout_status: "submitted", transfer_id: transferId };
      } catch (error: unknown) {
        const disposition = providerCommandFailureDisposition({
          providerAccepted,
          providerRejected: error instanceof PaytrProviderError && error.definitelyRejected,
        });
        await Payouts.updateOne(payoutId, {
          payout_status: disposition === "failed" ? "failed" : "instruction_pending",
          failure_reason: safeError(error),
        });
        await writeAudit(schema, {
          idempotencyKey,
          action: "payout_transfer",
          outcome: "failed",
          actorId: userId,
          orderId: numericId(payout.order_id, "payout.order_id"),
          payoutId,
        });
        throw error;
      }
    },

    updatePaymentAccount: async (input) => {
      const venueId = positiveInteger(input.venueId, "venueId");
      const userId = requiredString(input.userId, "userId");
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      if (!actor.isAdmin && actor.venueId !== venueId) {
        throw appError(403, "VENUE_ACCESS_DENIED", "User cannot update this restaurant account");
      }
      const legalName = requiredString(input.legal_name, "legal_name");
      const taxId = requiredString(input.tax_id, "tax_id");
      const encrypted = encryptIban(requiredString(input.iban, "iban"), paymentAccountKey(context.env));
      const status = actor.isAdmin
        ? optionalStatus(input.activation_status, [
            "pending",
            "under_review",
            "approved",
            "rejected",
            "suspended",
          ]) ?? "under_review"
        : "under_review";
      const payload: Row = {
        venue_id: venueId,
        activation_status: status,
        legal_name: legalName,
        tax_id: taxId,
        transfer_iban_ciphertext: encrypted.ciphertext,
        transfer_iban_iv: encrypted.iv,
        transfer_iban_auth_tag: encrypted.authTag,
        masked_iban: encrypted.masked,
        onboarding_documents: isRecord(input.onboarding_documents)
          ? input.onboarding_documents
          : null,
        accepts_online_payment: input.accepts_online_payment === true,
        accepts_cash_on_delivery: input.accepts_cash_on_delivery !== false,
        accepts_card_on_delivery: input.accepts_card_on_delivery !== false,
        ...(actor.isAdmin && status === "approved"
          ? { reviewed_by: userId, reviewed_at: new Date().toISOString() }
          : {}),
      };
      const Accounts = items("venue_payment_accounts", schema);
      const existing = await readOneByFilter(Accounts, { venue_id: { _eq: venueId } });
      const accountId = existing
        ? numericId(existing.id, "account.id")
        : numericId(await Accounts.createOne(payload), "account.id");
      if (existing) await Accounts.updateOne(accountId, payload);
      await items("venues", schema).updateOne(venueId, {
        accepts_online_payment: payload.accepts_online_payment,
        accepts_cash_on_delivery: payload.accepts_cash_on_delivery,
        accepts_card_on_delivery: payload.accepts_card_on_delivery,
        paytr_marketplace_status: status,
      });
      return {
        id: accountId,
        activation_status: status,
        masked_iban: encrypted.masked,
        accepts_online_payment: payload.accepts_online_payment,
        accepts_cash_on_delivery: payload.accepts_cash_on_delivery,
        accepts_card_on_delivery: payload.accepts_card_on_delivery,
      };
    },

    reviewPaymentAccount: async (input) => {
      const venueId = positiveInteger(input.venueId, "venueId");
      const userId = requiredString(input.userId, "userId");
      const idempotencyKey = commandKey(input.idempotency_key);
      const schema = await context.getSchema();
      const actor = await readActor(schema, userId);
      if (!actor.isAdmin) {
        throw appError(403, "ADMIN_REQUIRED", "Administrator access is required");
      }
      const status = optionalStatus(input.activation_status, ["approved", "rejected", "suspended"]);
      if (!status) {
        throw appError(400, "INVALID_ACCOUNT_STATUS", "Review status is required");
      }
      const Accounts = items("venue_payment_accounts", schema);
      const account = await readOneByFilter(Accounts, { venue_id: { _eq: venueId } });
      if (!account) {
        throw appError(404, "PAYMENT_ACCOUNT_NOT_FOUND", "Payment account was not found");
      }
      await writeAudit(schema, {
        idempotencyKey,
        action: "payment_account_review",
        outcome: "started",
        actorId: userId,
      });
      const reviewedAt = new Date().toISOString();
      await context.database.transaction(async (trx) => {
        await items("venue_payment_accounts", schema, trx).updateOne(
          numericId(account.id, "account.id"),
          {
            activation_status: status,
            reviewed_by: userId,
            reviewed_at: reviewedAt,
          },
        );
        await items("venues", schema, trx).updateOne(venueId, {
          paytr_marketplace_status: status,
          accepts_online_payment:
            status === "approved" && account.accepts_online_payment === true,
        });
      });
      await writeAudit(schema, {
        idempotencyKey,
        action: "payment_account_review",
        outcome: "completed",
        actorId: userId,
      });
      return { activation_status: status };
    },

    runLifecycle: async () => {
      const schema = await context.getSchema();
      const now = new Date();
      const nowIso = now.toISOString();
      let reconciled = 0;
      let refunded = 0;
      let submitted = 0;

      const expiredAttempts = await items("order_payment_attempts", schema).readByQuery({
        filter: {
          _and: [
            { attempt_status: { _eq: "pending" } },
            { expires_at: { _lte: nowIso } },
          ],
        },
        fields: ["*"],
        sort: ["expires_at"],
        limit: 100,
      });
      for (const attempt of expiredAttempts) {
        try {
          const orderContext = await readOrderContext(
            schema,
            numericId(attempt.order_id, "attempt.order_id"),
          );
          await reconcileAttempt(schema, orderContext, attempt);
          reconciled += 1;
        } catch (error: unknown) {
          context.logger.error(
            `[payments] payment-attempt lifecycle failed id=${String(attempt.id)}: ${safeError(error)}`,
          );
        }
      }

      const timedOutPayments = await items("online_order_payments", schema).readByQuery({
        filter: {
          _and: [
            { payment_status: { _in: ["succeeded", "partially_refunded"] } },
            { acceptance_deadline_at: { _lte: nowIso } },
            { order_id: { order_status: { _eq: "pending" } } },
          ],
        },
        fields: ["order_id"],
        sort: ["acceptance_deadline_at"],
        limit: 100,
      });
      for (const payment of timedOutPayments) {
        const orderId = numericId(payment.order_id, "payment.order_id");
        try {
          await cancelForAcceptanceTimeout(schema, await readOrderContext(schema, orderId));
          refunded += 1;
        } catch (error: unknown) {
          context.logger.error(
            `[payments] acceptance-timeout lifecycle failed order=${orderId}: ${safeError(error)}`,
          );
        }
      }

      const failedAcceptanceRefunds = await items("order_refunds", schema).readByQuery({
        filter: {
          _and: [
            { refund_type: { _eq: "acceptance_timeout" } },
            { refund_status: { _eq: "failed" } },
          ],
        },
        fields: ["order_id"],
        sort: ["date_created"],
        limit: 100,
      });
      const retriedAcceptanceOrderIds = new Set<number>();
      for (const refund of failedAcceptanceRefunds) {
        const orderId = numericId(refund.order_id, "refund.order_id");
        if (retriedAcceptanceOrderIds.has(orderId)) continue;
        retriedAcceptanceOrderIds.add(orderId);
        try {
          await cancelForAcceptanceTimeout(schema, await readOrderContext(schema, orderId));
          refunded += 1;
        } catch (error: unknown) {
          context.logger.error(
            `[payments] acceptance-timeout refund retry failed order=${orderId}: ${safeError(error)}`,
          );
        }
      }

      const lifecycleActor = optionalEnv(context.env, "MARKETPLACE_LIFECYCLE_ACTOR_ID");
      if (lifecycleActor) {
        const eligiblePayouts = await items("venue_payouts", schema).readByQuery({
          filter: {
            _and: [
              { payout_status: { _eq: "scheduled" } },
              { eligible_on: { _lte: nowIso.slice(0, 10) } },
            ],
          },
          fields: ["id"],
          sort: ["eligible_on"],
          limit: 100,
        });
        for (const payout of eligiblePayouts) {
          const payoutId = numericId(payout.id, "payout.id");
          try {
            await application.submitPayout({
              payoutId,
              userId: lifecycleActor,
              idempotency_key: `scheduled-payout-${payoutId}`,
            });
            submitted += 1;
          } catch (error: unknown) {
            context.logger.error(
              `[payments] payout lifecycle failed id=${payoutId}: ${safeError(error)}`,
            );
          }
        }
      } else {
        context.logger.warn(
          "[payments] MARKETPLACE_LIFECYCLE_ACTOR_ID is not set; eligible payouts remain scheduled",
        );
      }

      return { reconciled, refunded, submitted };
    },
  };

  return application;

  async function requestIframeToken(
    schema: unknown,
    orderContext: OrderContext,
    attempt: Row,
    actor: Actor,
    userIp: string,
  ): Promise<Row> {
    const orderId = numericId(orderContext.order.id, "order.id");
    const lines = await items("order_items", schema).readByQuery({
      filter: { order_id: { _eq: orderId } },
      fields: ["quantity", "unit_price_minor", { product_id: ["name"] }],
      limit: -1,
    });
    const basket: Array<[string, string, number]> = lines.map((line) => [
      relatedName(line.product_id) ?? "Order item",
      (positiveInteger(line.unit_price_minor, "unit_price_minor") / 100).toFixed(2),
      positiveInteger(line.quantity, "quantity"),
    ]);
    const amountMinor = positiveInteger(attempt.amount_minor, "attempt.amount_minor");
    const currency = stringField(attempt, "currency");
    const token = await provider().createIframe({
      merchantOid: stringField(attempt, "merchant_oid"),
      userIp,
      email: actor.email,
      paymentAmountMinor: amountMinor,
      currency: currency === "TRY" ? "TL" : currency,
      basket,
      userName: actor.name,
      userAddress: "Türkiye",
      userPhone: actor.phone,
      merchantOkUrl: requiredEnv(context.env, "PAYTR_ORDER_OK_URL"),
      merchantFailUrl: requiredEnv(context.env, "PAYTR_ORDER_FAIL_URL"),
      callbackUrl: requiredEnv(context.env, "PAYTR_ORDER_CALLBACK_URL"),
      timeoutLimitMinutes: 15,
      testMode: envBoolean(context.env, "PAYTR_ORDER_TEST_MODE", false),
    });
    return {
      token: token.token,
      merchant_oid: attempt.merchant_oid,
      expires_at: attempt.expires_at,
    };
  }

  async function reconcileAttempt(
    schema: unknown,
    orderContext: OrderContext,
    attempt: Row,
  ): Promise<"captured" | "not_captured"> {
    const merchantOid = stringField(attempt, "merchant_oid");
    const status = await provider().queryStatus(merchantOid);
    if (status.captured) {
      if (
        status.amountMinor !== positiveInteger(attempt.amount_minor, "attempt.amount_minor") ||
        status.currency !== stringField(attempt, "currency")
      ) {
        throw appError(409, "PAYTR_STATUS_MISMATCH", "PayTR status amount or currency differs");
      }
      await applyProviderResult(schema, {
        attempt,
        status: "success",
        amountMinor: status.amountMinor,
        currency: status.currency,
        paymentType: status.paymentType,
        eventKey: sha256(
          `status:${merchantOid}:${status.amountMinor}:${status.currency}:${status.paidAt ?? "unknown"}`,
        ),
        eventType: "status_query",
        payloadHash: sha256(`${merchantOid}:${status.amountMinor}:${status.currency}`),
      });
      return "captured";
    }
    if (Date.now() >= Date.parse(stringField(attempt, "expires_at"))) {
      await context.database.transaction(async (trx) => {
        const current = await trx("order_payment_attempts")
          .where({ id: numericId(attempt.id, "attempt.id") })
          .forUpdate()
          .first("*");
        if (!current || current.attempt_status !== "pending") return;
        await items("order_payment_attempts", schema, trx).updateOne(
          numericId(attempt.id, "attempt.id"),
          { attempt_status: "expired", status_checked_at: new Date().toISOString() },
        );
        await items("online_order_payments", schema, trx).updateOne(
          numericId(orderContext.payment.id, "payment.id"),
          { payment_status: "expired" },
        );
        await items("orders", schema, trx).updateOne(
          numericId(orderContext.order.id, "order.id"),
          { order_status: "expired" },
        );
      });
    }
    return "not_captured";
  }

  async function applyProviderResult(
    schema: unknown,
    input: {
      attempt: Row;
      status: "success" | "failed";
      amountMinor: number;
      currency: string;
      paymentType: string | null;
      eventKey: string;
      eventType: "callback" | "status_query";
      payloadHash: string;
    },
  ): Promise<{ refundExcessAttempt: boolean }> {
    if (await providerEventExists(schema, input.eventKey)) {
      return { refundExcessAttempt: false };
    }
    return context.database.transaction(async (trx) => {
      const attempt = await trx("order_payment_attempts")
        .where({ id: numericId(input.attempt.id, "attempt.id") })
        .forUpdate()
        .first("*");
      if (!attempt) throw appError(404, "PAYMENT_ATTEMPT_NOT_FOUND", "Payment attempt was not found");
      const payment = await trx("online_order_payments")
        .where({ id: numericId(attempt.payment_id, "attempt.payment_id") })
        .forUpdate()
        .first("*");
      if (!payment) throw appError(404, "PAYMENT_NOT_FOUND", "Online payment was not found");
      const order = await trx("orders")
        .where({ id: numericId(attempt.order_id, "attempt.order_id") })
        .forUpdate()
        .first("*");
      if (!order) throw appError(404, "ORDER_NOT_FOUND", "Order was not found");

      const Events = items("payment_provider_events", schema, trx);
      const existing = await Events.readByQuery({
        filter: { event_key: { _eq: input.eventKey } },
        fields: ["id"],
        limit: 1,
      });
      if (existing[0]) return { refundExcessAttempt: false };
      const eventId = numericId(
        await Events.createOne({
          payment_id: payment.id,
          attempt_id: attempt.id,
          event_key: input.eventKey,
          event_type: input.eventType,
          payload_hash: input.payloadHash,
          processing_status: "received",
        }),
        "event.id",
      );

      try {
        const applied = applyVerifiedPaymentCallback(
          {
            status: paymentStatus(payment),
            amountMinor: positiveInteger(payment.amount_minor, "payment.amount_minor"),
            currency: stringField(payment, "currency"),
          },
          {
            id: numericId(attempt.id, "attempt.id"),
            status: attemptStatus(attempt),
            amountMinor: positiveInteger(attempt.amount_minor, "attempt.amount_minor"),
            currency: stringField(attempt, "currency"),
          },
          {
            status: input.status,
            amountMinor: input.amountMinor,
            currency: input.currency,
            occurredAt: new Date().toISOString(),
          },
        );
        const now = new Date().toISOString();
        await items("order_payment_attempts", schema, trx).updateOne(
          numericId(attempt.id, "attempt.id"),
          {
            attempt_status: applied.attemptStatus,
            captured_at: applied.attemptStatus === "succeeded" ? now : null,
            provider_payment_type: input.paymentType,
            failure_message: applied.attemptStatus === "failed" ? "Provider reported failure" : null,
          },
        );
        if (applied.outcome === "captured") {
          await items("online_order_payments", schema, trx).updateOne(
            numericId(payment.id, "payment.id"),
            {
              payment_status: "succeeded",
              paid_at: now,
              acceptance_deadline_at: applied.acceptanceDeadlineAt,
            },
          );
          await items("orders", schema, trx).updateOne(numericId(order.id, "order.id"), {
            order_status: "pending",
            acceptance_deadline_at: applied.acceptanceDeadlineAt,
          });
          const Verifications = items("order_delivery_verifications", schema, trx);
          const existingVerification = await Verifications.readByQuery({
            filter: { order_id: { _eq: order.id } },
            fields: ["id"],
            limit: 1,
          });
          if (!existingVerification[0]) {
            const code = deriveDeliveryCode(numericId(order.id, "order.id"), deliveryPepper(context.env));
            await Verifications.createOne({
              order_id: order.id,
              code_hash: hashDeliveryCode(
                numericId(order.id, "order.id"),
                code,
                deliveryPepper(context.env),
              ),
              failed_attempts: 0,
            });
          }
        } else if (applied.outcome === "failed") {
          await items("online_order_payments", schema, trx).updateOne(
            numericId(payment.id, "payment.id"),
            { payment_status: "failed" },
          );
        }
        await Events.updateOne(eventId, {
          processing_status: "processed",
          processed_at: now,
        });
        return { refundExcessAttempt: applied.refundExcessAttempt };
      } catch (error: unknown) {
        await Events.updateOne(eventId, {
          processing_status: "rejected",
          failure_reason: safeError(error),
          processed_at: new Date().toISOString(),
        });
        throw error;
      }
    });
  }

  async function performRefund(schema: unknown, request: RefundRequest): Promise<Row> {
    const Refunds = items("order_refunds", schema);
    const existingRefund = await readOneByFilter(Refunds, {
      request_idempotency_key: { _eq: request.idempotencyKey },
    });
    if (existingRefund) return existingRefund;

    const claim = await context.database.transaction(async (trx) => {
      const lockedPayment = await trx("online_order_payments")
        .where({ order_id: request.orderId })
        .forUpdate()
        .first("*");
      if (!lockedPayment) {
        throw appError(404, "ONLINE_PAYMENT_NOT_FOUND", "Online payment was not found");
      }
      const TxRefunds = items("order_refunds", schema, trx);
      const repeated = await readOneByFilter(TxRefunds, {
        request_idempotency_key: { _eq: request.idempotencyKey },
      });
      if (repeated) return { existing: repeated, prepared: null };

      const orderContext = await readOrderContext(schema, request.orderId, true, trx);
      if (!["succeeded", "partially_refunded"].includes(paymentStatus(orderContext.payment))) {
        throw appError(409, "PAYMENT_NOT_REFUNDABLE", "Payment is not refundable");
      }
      const amounts = await refundAmounts(schema, orderContext, request, trx);
      const claimedSettlementRefunds = await TxRefunds.readByQuery({
        filter: {
          _and: [
            { order_id: { _eq: request.orderId } },
            { refund_status: { _in: ["processing", "succeeded"] } },
          ],
        },
        fields: [
          "food_amount_minor",
          "commission_reversal_minor",
          "commission_vat_reversal_minor",
          "withholding_reversal_minor",
        ],
        limit: -1,
      });
      const previousReversals = claimedSettlementRefunds.reduce(
        (totals, refund) => ({
          foodMinor:
            totals.foodMinor + nonNegativeInteger(refund.food_amount_minor, "refund.food_amount_minor"),
          commissionMinor:
            totals.commissionMinor +
            nonNegativeInteger(refund.commission_reversal_minor, "refund.commission_reversal_minor"),
          commissionVatMinor:
            totals.commissionVatMinor +
            nonNegativeInteger(
              refund.commission_vat_reversal_minor,
              "refund.commission_vat_reversal_minor",
            ),
          withholdingMinor:
            totals.withholdingMinor +
            nonNegativeInteger(refund.withholding_reversal_minor, "refund.withholding_reversal_minor"),
        }),
        { foodMinor: 0, commissionMinor: 0, commissionVatMinor: 0, withholdingMinor: 0 },
      );
      const allocation = allocatePartialRefund({
        refundFoodMinor: amounts.foodMinor,
        refundDeliveryMinor: amounts.deliveryMinor,
        originalFoodMinor: positiveInteger(
          orderContext.payment.food_subtotal_minor,
          "payment.food_subtotal_minor",
        ),
        originalCommissionMinor: nonNegativeInteger(
          orderContext.payment.commission_minor,
          "payment.commission_minor",
        ),
        originalCommissionVatMinor: nonNegativeInteger(
          orderContext.payment.commission_vat_minor,
          "payment.commission_vat_minor",
        ),
        originalWithholdingMinor: nonNegativeInteger(
          orderContext.payment.withholding_minor,
          "payment.withholding_minor",
        ),
        previousRefundFoodMinor: previousReversals.foodMinor,
        previousCommissionReversalMinor: previousReversals.commissionMinor,
        previousCommissionVatReversalMinor: previousReversals.commissionVatMinor,
        previousWithholdingReversalMinor: previousReversals.withholdingMinor,
      });
      const attempt = request.attemptId
        ? orderContext.attempts.find((candidate) => Number(candidate.id) === request.attemptId)
        : [...orderContext.attempts]
            .reverse()
            .find((candidate) => candidate.attempt_status === "succeeded");
      if (!attempt) {
        throw appError(409, "CAPTURE_NOT_FOUND", "Captured payment attempt was not found");
      }

      const refundId = numericId(
        await TxRefunds.createOne({
          request_idempotency_key: request.idempotencyKey,
          order_id: request.orderId,
          payment_id: orderContext.payment.id,
          attempt_id: attempt.id,
          requested_by: request.actorId,
          refund_type: request.refundType,
          refund_status: "processing",
          amount_minor: allocation.refundTotalMinor,
          food_amount_minor: amounts.foodMinor,
          delivery_amount_minor: amounts.deliveryMinor,
          commission_reversal_minor: allocation.commissionReversalMinor,
          commission_vat_reversal_minor: allocation.commissionVatReversalMinor,
          withholding_reversal_minor: allocation.withholdingReversalMinor,
          post_transfer_adjustment: amounts.postTransfer,
          provider_reference: null,
          reason: request.reason,
        }),
        "refund.id",
      );
      const RefundItems = items("order_refund_items", schema, trx);
      for (const [index, line] of amounts.itemLines.entries()) {
        await RefundItems.createOne({
          refund_line_key: `${refundId}:${line.orderItemId}:${index}`,
          refund_id: refundId,
          order_item_id: line.orderItemId,
          quantity: line.quantity,
          unit_price_minor: line.unitPriceMinor,
          amount_minor: line.amountMinor,
        });
      }
      return {
        existing: null,
        prepared: { allocation, amounts, attempt, orderContext, refundId },
      };
    });
    if (claim.existing) return claim.existing;
    if (!claim.prepared) {
      throw appError(500, "REFUND_CLAIM_FAILED", "Refund request could not be claimed");
    }
    const { allocation, amounts, attempt, orderContext, refundId } = claim.prepared;

    await writeAudit(schema, {
      idempotencyKey: request.idempotencyKey,
      action: "order_refund",
      outcome: "started",
      actorId: request.actorId,
      orderId: request.orderId,
      paymentId: numericId(orderContext.payment.id, "payment.id"),
    });
    const referenceNo = `KYR${refundId}`;
    let providerAccepted = false;
    try {
      const result = await provider().refund({
        merchantOid: stringField(attempt, "merchant_oid"),
        returnAmount: (allocation.refundTotalMinor / 100).toFixed(2),
        referenceNo,
      });
      providerAccepted = true;
      const total = positiveInteger(orderContext.payment.amount_minor, "payment.amount_minor");
      await context.database.transaction(async (trx) => {
        const currentPayment = await trx("online_order_payments")
          .where({ id: numericId(orderContext.payment.id, "payment.id") })
          .forUpdate()
          .first("*");
        if (!currentPayment) {
          throw appError(404, "PAYMENT_NOT_FOUND", "Online payment was not found");
        }
        const updatedRefunded =
          nonNegativeInteger(currentPayment.refunded_amount_minor, "refunded_amount_minor") +
          allocation.refundTotalMinor;
        await items("order_refunds", schema, trx).updateOne(refundId, {
          refund_status: "succeeded",
          provider_reference: result.reference ?? referenceNo,
          completed_at: new Date().toISOString(),
        });
        await items("online_order_payments", schema, trx).updateOne(
          numericId(orderContext.payment.id, "payment.id"),
          {
            refunded_amount_minor: updatedRefunded,
            payment_status: updatedRefunded >= total ? "refunded" : "partially_refunded",
          },
        );
        const payouts = await items("venue_payouts", schema, trx).readByQuery({
          filter: { order_id: { _eq: request.orderId } },
          fields: ["*"],
          limit: 1,
        });
        const payout = payouts[0];
        if (payout && ["scheduled", "failed"].includes(String(payout.payout_status))) {
          const payoutNet = nonNegativeInteger(payout.net_minor, "payout.net_minor");
          const appliedDebit = Math.min(payoutNet, allocation.venueDebitMinor);
          const remainingDebit = allocation.venueDebitMinor - appliedDebit;
          const adjustment = Number(payout.refund_adjustment_minor ?? 0) - appliedDebit;
          await items("venue_payouts", schema, trx).updateOne(numericId(payout.id, "payout.id"), {
            refund_adjustment_minor: adjustment,
            net_minor: payoutNet - appliedDebit,
            ...(payoutNet === appliedDebit ? { payout_status: "offset" } : {}),
          });
          if (remainingDebit > 0) {
            await items("venue_balance_adjustments", schema, trx).createOne({
              venue_id: numericId(orderContext.order.venue_id, "order.venue_id"),
              refund_id: refundId,
              source_payout_id: numericId(payout.id, "payout.id"),
              amount_minor: remainingDebit,
              applied_amount_minor: 0,
              adjustment_status: "pending",
              reason: request.reason,
            });
          }
        } else if (
          amounts.postTransfer &&
          allocation.venueDebitMinor > 0 &&
          payout &&
          payoutRequiresBalanceAdjustment(String(payout.payout_status))
        ) {
          const Adjustments = items("venue_balance_adjustments", schema, trx);
          const existingAdjustment = await readOneByFilter(Adjustments, {
            refund_id: { _eq: refundId },
          });
          if (!existingAdjustment) {
            await Adjustments.createOne({
              venue_id: numericId(orderContext.order.venue_id, "order.venue_id"),
              refund_id: refundId,
              source_payout_id: numericId(payout.id, "payout.id"),
              amount_minor: allocation.venueDebitMinor,
              applied_amount_minor: 0,
              adjustment_status: "pending",
              reason: request.reason,
            });
          }
        }
      });
      await writeAudit(schema, {
        idempotencyKey: request.idempotencyKey,
        action: "order_refund",
        outcome: "completed",
        actorId: request.actorId,
        orderId: request.orderId,
        paymentId: numericId(orderContext.payment.id, "payment.id"),
        refundId,
      });
      return items("order_refunds", schema).readOne(refundId, { fields: ["*"] });
    } catch (error: unknown) {
      const disposition = providerCommandFailureDisposition({
        providerAccepted,
        providerRejected: error instanceof PaytrProviderError && error.definitelyRejected,
      });
      await Refunds.updateOne(refundId, {
        refund_status: disposition === "failed" ? "failed" : "processing",
        failure_reason: safeError(error),
      });
      await writeAudit(schema, {
        idempotencyKey: request.idempotencyKey,
        action: "order_refund",
        outcome: "failed",
        actorId: request.actorId,
        orderId: request.orderId,
        paymentId: numericId(orderContext.payment.id, "payment.id"),
        refundId,
      });
      throw error;
    }
  }

  async function refundAmounts(
    schema: unknown,
    orderContext: OrderContext,
    request: RefundRequest,
    trx?: DatabaseTransaction,
  ): Promise<{
    foodMinor: number;
    deliveryMinor: number;
    postTransfer: boolean;
    itemLines: Array<{
      orderItemId: number;
      quantity: number;
      unitPriceMinor: number;
      amountMinor: number;
    }>;
  }> {
    const refunds = await items("order_refunds", schema, trx).readByQuery({
      filter: {
        _and: [
          { order_id: { _eq: request.orderId } },
          { refund_status: { _in: ["processing", "succeeded"] } },
        ],
      },
      fields: ["food_amount_minor", "delivery_amount_minor"],
      limit: -1,
    });
    const refundedFood = refunds.reduce((sum, row) => sum + Number(row.food_amount_minor ?? 0), 0);
    const refundedDelivery = refunds.reduce(
      (sum, row) => sum + Number(row.delivery_amount_minor ?? 0),
      0,
    );
    const foodRemaining =
      positiveInteger(orderContext.payment.food_subtotal_minor, "food_subtotal_minor") -
      refundedFood;
    const deliveryRemaining =
      nonNegativeInteger(orderContext.payment.delivery_fee_minor, "delivery_fee_minor") -
      refundedDelivery;
    let foodMinor = 0;
    let deliveryMinor = request.includeDeliveryFee ? deliveryRemaining : 0;
    const itemLines: Array<{
      orderItemId: number;
      quantity: number;
      unitPriceMinor: number;
      amountMinor: number;
    }> = [];

    if (request.itemRequests && request.itemRequests.length > 0) {
      const orderItems = await items("order_items", schema, trx).readByQuery({
        filter: {
          _and: [
            { order_id: { _eq: request.orderId } },
            { id: { _in: request.itemRequests.map((item) => item.orderItemId) } },
          ],
        },
        fields: ["id", "quantity", "unit_price_minor"],
        limit: -1,
      });
      const byId = new Map(orderItems.map((item) => [Number(item.id), item]));
      const claimedItems = await items("order_refund_items", schema, trx).readByQuery({
        filter: {
          _and: [
            { order_item_id: { _in: request.itemRequests.map((item) => item.orderItemId) } },
            { refund_id: { refund_status: { _in: ["processing", "succeeded"] } } },
          ],
        },
        fields: ["order_item_id", "quantity"],
        limit: -1,
      });
      const claimedByItem = new Map<number, number>();
      for (const claimed of claimedItems) {
        const orderItemId = numericId(claimed.order_item_id, "refund_item.order_item_id");
        claimedByItem.set(
          orderItemId,
          (claimedByItem.get(orderItemId) ?? 0) +
            positiveInteger(claimed.quantity, "refund_item.quantity"),
        );
      }
      foodMinor = request.itemRequests.reduce((sum, requested) => {
        const item = byId.get(requested.orderItemId);
        if (!item) {
          throw appError(422, "REFUND_ITEM_INVALID", "Refund item quantity is invalid");
        }
        const unitPriceMinor = positiveInteger(item.unit_price_minor, "item.unit_price_minor");
        let amountMinor: number;
        try {
          amountMinor = calculateRefundLineAmount({
            purchasedQuantity: positiveInteger(item.quantity, "item.quantity"),
            previouslyClaimedQuantity: claimedByItem.get(requested.orderItemId) ?? 0,
            requestedQuantity: requested.quantity,
            unitPriceMinor,
          });
        } catch {
          throw appError(422, "REFUND_ITEM_INVALID", "Refund item quantity is invalid");
        }
        claimedByItem.set(
          requested.orderItemId,
          (claimedByItem.get(requested.orderItemId) ?? 0) + requested.quantity,
        );
        itemLines.push({
          orderItemId: requested.orderItemId,
          quantity: requested.quantity,
          unitPriceMinor,
          amountMinor,
        });
        return sum + amountMinor;
      }, 0);
    } else if (request.amountMinor) {
      foodMinor = Math.min(request.amountMinor, foodRemaining);
      deliveryMinor = request.amountMinor - foodMinor;
    }
    if (request.refundType === "full" || request.refundType === "customer_cancel" || request.refundType === "acceptance_timeout") {
      foodMinor = foodRemaining;
      deliveryMinor = deliveryRemaining;
    }
    if (
      foodMinor < 0 ||
      deliveryMinor < 0 ||
      foodMinor > foodRemaining ||
      deliveryMinor > deliveryRemaining ||
      foodMinor + deliveryMinor <= 0
    ) {
      throw appError(422, "REFUND_AMOUNT_INVALID", "Refund exceeds the remaining payment amount");
    }
    const payouts = await items("venue_payouts", schema, trx).readByQuery({
      filter: { order_id: { _eq: request.orderId } },
      fields: ["payout_status"],
      limit: 1,
    });
    return {
      foodMinor,
      deliveryMinor,
      itemLines,
      postTransfer: Boolean(
        payouts[0] && payoutRequiresBalanceAdjustment(String(payouts[0].payout_status)),
      ),
    };
  }

  async function expireAcceptanceIfNeeded(schema: unknown, orderContext: OrderContext): Promise<void> {
    const deadline = optionalString(orderContext.payment.acceptance_deadline_at);
    if (
      orderContext.order.order_status === "pending" &&
      ["succeeded", "partially_refunded"].includes(
        String(orderContext.payment.payment_status),
      ) &&
      deadline &&
      Date.now() >= Date.parse(deadline)
    ) {
      await cancelForAcceptanceTimeout(schema, orderContext);
    }
  }

  async function cancelForAcceptanceTimeout(schema: unknown, orderContext: OrderContext): Promise<void> {
    const orderId = numericId(orderContext.order.id, "order.id");
    const acceptanceRefunds = await items("order_refunds", schema).readByQuery({
      filter: {
        _and: [
          { order_id: { _eq: orderId } },
          { refund_type: { _eq: "acceptance_timeout" } },
        ],
      },
      fields: ["refund_status"],
      limit: -1,
    });
    const failedRefundCount = acceptanceRefunds.filter(
      (refund) => refund.refund_status === "failed",
    ).length;
    const hasUncertainRefund = acceptanceRefunds.some(
      (refund) => refund.refund_status === "processing",
    );
    if (orderContext.order.order_status === "pending") {
      const updated = await context.database.transaction(async (trx) =>
        trx("orders").where({ id: orderId, order_status: "pending" }).update({
          order_status: "cancelled",
          cancellation_reason: "Restaurant acceptance window expired",
        }),
      );
      if (updated !== 1) return;
    } else if (orderContext.order.order_status !== "cancelled" || failedRefundCount === 0 || hasUncertainRefund) {
      return;
    }
    const remaining =
      positiveInteger(orderContext.payment.amount_minor, "amount_minor") -
      nonNegativeInteger(orderContext.payment.refunded_amount_minor, "refunded_amount_minor");
    if (remaining > 0) {
      await performRefund(schema, {
        orderId,
        actorId: null,
        refundType: "acceptance_timeout",
        reason: "Restaurant acceptance window expired",
        idempotencyKey: acceptanceTimeoutRefundIdempotencyKey(orderId, failedRefundCount),
        amountMinor: remaining,
        includeDeliveryFee: true,
      });
    }
  }

  async function readOrderContext(
    schema: unknown,
    orderId: number,
    requirePayment = true,
    trx?: DatabaseTransaction,
  ): Promise<OrderContext> {
    const Orders = items("orders", schema, trx);
    let order: Row;
    try {
      order = await Orders.readOne(orderId, { fields: ["*"] });
    } catch {
      throw appError(404, "ORDER_NOT_FOUND", "Order was not found");
    }
    const payments = await items("online_order_payments", schema, trx).readByQuery({
      filter: { order_id: { _eq: orderId } },
      fields: ["*"],
      limit: 1,
    });
    const payment = payments[0];
    if (!payment) {
      if (!requirePayment) {
        return { order, payment: { payment_status: "pending", refunded_amount_minor: 0 }, attempts: [] };
      }
      throw appError(404, "ONLINE_PAYMENT_NOT_FOUND", "Online payment was not found");
    }
    const attempts = await items("order_payment_attempts", schema, trx).readByQuery({
      filter: { payment_id: { _eq: payment.id } },
      fields: ["*"],
      sort: ["id"],
      limit: -1,
    });
    return { order, payment, attempts };
  }

  async function readActor(schema: unknown, userId: string): Promise<Actor> {
    let user: Row;
    try {
      user = await new context.services.UsersService({
        schema,
        accountability: { admin: true },
      }).readOne(userId, {
        fields: ["id", "email", "first_name", "last_name", "phone", "venue_id", "role.id", "role.name"],
      });
    } catch {
      throw appError(401, "AUTHENTICATION_REQUIRED", "User was not found");
    }
    const role = isRecord(user.role) ? user.role : {};
    const roleName = optionalString(role.name)?.toLowerCase() ?? "";
    const adminRoleId = optionalEnv(context.env, "ADMIN_ROLE_ID");
    return {
      id: userId,
      email: requiredString(user.email, "email"),
      name:
        [optionalString(user.first_name), optionalString(user.last_name)].filter(Boolean).join(" ") ||
        "Customer",
      phone: optionalString(user.phone) ?? "05000000000",
      venueId: relatedId(user.venue_id),
      isAdmin:
        roleName === "delivr admin" ||
        roleName === "administrator" ||
        (adminRoleId !== null && optionalString(role.id) === adminRoleId),
    };
  }

  function items(collection: string, schema: unknown, trx?: DatabaseTransaction): ItemsServiceLike {
    return new context.services.ItemsService(collection, {
      schema,
      ...(trx ? { knex: trx } : {}),
      accountability: { admin: true },
    });
  }

  async function providerEventExists(schema: unknown, eventKey: string): Promise<boolean> {
    const rows = await items("payment_provider_events", schema).readByQuery({
      filter: { event_key: { _eq: eventKey } },
      fields: ["id"],
      limit: 1,
    });
    return Boolean(rows[0]);
  }

  async function writeAudit(
    schema: unknown,
    audit: {
      idempotencyKey: string;
      action: string;
      outcome: "started" | "completed" | "failed" | "cancelled" | "duplicate";
      actorId: string | null;
      orderId?: number;
      paymentId?: number;
      refundId?: number;
      payoutId?: number;
    },
  ): Promise<void> {
    const Audits = items("payment_audit_logs", schema);
    const key = `${audit.idempotencyKey}:${audit.outcome}`;
    const existing = await readOneByFilter(Audits, { idempotency_key: { _eq: key } });
    if (existing) return;
    await Audits.createOne({
      actor_id: audit.actorId,
      order_id: audit.orderId ?? null,
      payment_id: audit.paymentId ?? null,
      refund_id: audit.refundId ?? null,
      payout_id: audit.payoutId ?? null,
      idempotency_key: key,
      action: audit.action,
      outcome: audit.outcome,
      metadata: null,
    });
  }
}

function credentials(env: Record<string, unknown>): PaytrCredentials {
  return {
    merchantId: requiredEnv(env, "PAYTR_MERCHANT_ID"),
    merchantKey: requiredEnv(env, "PAYTR_MERCHANT_KEY"),
    merchantSalt: requiredEnv(env, "PAYTR_MERCHANT_SALT"),
  };
}

function deliveryPepper(env: Record<string, unknown>): string {
  return requiredEnv(env, "PAYMENT_DELIVERY_CODE_PEPPER");
}

function paymentAccountKey(env: Record<string, unknown>): string {
  return requiredEnv(env, "PAYMENT_ACCOUNT_ENCRYPTION_KEY");
}

function requiredEnv(env: Record<string, unknown>, name: string): string {
  const value = optionalEnv(env, name);
  if (!value) throw appError(500, "PAYMENT_CONFIGURATION_MISSING", `${name} is not configured`);
  return value;
}

function optionalEnv(env: Record<string, unknown>, name: string): string | null {
  return optionalString(env[name]);
}

function envBoolean(env: Record<string, unknown>, name: string, fallback: boolean): boolean {
  const value = optionalString(env[name]);
  if (value === null) return fallback;
  return value === "1" || value.toLowerCase() === "true";
}

function assertCustomerOwnsOrder(order: Row, actor: Actor): void {
  if (relatedStringId(order.user_id) !== actor.id) {
    throw appError(403, "ORDER_ACCESS_DENIED", "User cannot access this order");
  }
}

function assertVenueCanManage(order: Row, actor: Actor): void {
  if (!actor.isAdmin && relatedId(order.venue_id) !== actor.venueId) {
    throw appError(403, "VENUE_ACCESS_DENIED", "User cannot manage this order");
  }
}

function callbackStatus(value: unknown): "success" | "failed" {
  if (value !== "success" && value !== "failed") {
    throw appError(400, "INVALID_PAYTR_CALLBACK", "PayTR callback status is invalid");
  }
  return value;
}

function paymentStatus(row: Row): "pending" | "succeeded" | "failed" | "expired" | "refunded" {
  const status = stringField(row, "payment_status");
  if (status === "partially_refunded") return "succeeded";
  if (!["pending", "succeeded", "failed", "expired", "refunded"].includes(status)) {
    throw appError(500, "INVALID_PAYMENT_STATE", "Payment state is invalid");
  }
  return status as "pending" | "succeeded" | "failed" | "expired" | "refunded";
}

function attemptStatus(row: Row): "pending" | "succeeded" | "failed" | "expired" | "refunded" {
  const status = stringField(row, "attempt_status");
  if (!["pending", "succeeded", "failed", "expired", "refunded"].includes(status)) {
    throw appError(500, "INVALID_ATTEMPT_STATE", "Payment attempt state is invalid");
  }
  return status as "pending" | "succeeded" | "failed" | "expired" | "refunded";
}

function commandKey(value: unknown): string {
  const key = requiredString(value, "idempotency_key");
  if (!/^[A-Za-z0-9-]{8,128}$/.test(key)) {
    throw appError(400, "INVALID_IDEMPOTENCY_KEY", "idempotency_key is invalid");
  }
  return key;
}

function parseRefundItems(value: unknown): Array<{ orderItemId: number; quantity: number }> {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) {
    throw appError(400, "REFUND_ITEMS_INVALID", "items must be a non-empty array");
  }
  return value.map((item) => {
    if (!isRecord(item)) throw appError(400, "REFUND_ITEMS_INVALID", "Refund item is invalid");
    return {
      orderItemId: positiveInteger(item.order_item_id, "order_item_id"),
      quantity: positiveInteger(item.quantity, "quantity"),
    };
  });
}

function positiveInteger(value: unknown, field: string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw appError(400, "INVALID_REQUEST", `${field} must be a positive integer`);
  }
  return parsed;
}

function nonNegativeInteger(value: unknown, field: string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw appError(500, "INVALID_FINANCIAL_RECORD", `${field} must be a non-negative integer`);
  }
  return parsed;
}

function numericId(value: unknown, field: string): number {
  const related = isRecord(value) ? value.id : value;
  const parsed = Number(related);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw appError(500, "INVALID_FINANCIAL_RECORD", `${field} is invalid`);
  }
  return parsed;
}

function relatedId(value: unknown): number | null {
  if (value == null) return null;
  const raw = isRecord(value) ? value.id : value;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function relatedStringId(value: unknown): string | null {
  if (value == null) return null;
  const raw = isRecord(value) ? value.id : value;
  return typeof raw === "string" && raw ? raw : null;
}

function relatedName(value: unknown): string | null {
  return isRecord(value) ? optionalString(value.name) : null;
}

function requiredString(value: unknown, field: string): string {
  const result = optionalString(value);
  if (!result) throw appError(400, "INVALID_REQUEST", `${field} is required`);
  return result;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function stringField(row: Row, field: string): string {
  const value = optionalString(row[field]);
  if (!value) throw appError(500, "INVALID_FINANCIAL_RECORD", `${field} is missing`);
  return value;
}

function optionalStatus(value: unknown, allowed: string[]): string | null {
  if (value == null) return null;
  const status = requiredString(value, "activation_status");
  if (!allowed.includes(status)) {
    throw appError(400, "INVALID_REQUEST", "activation_status is invalid");
  }
  return status;
}

async function readOneByFilter(
  service: ItemsServiceLike,
  filter: Row,
): Promise<Row | null> {
  const rows = await service.readByQuery({ filter, fields: ["*"], limit: 1 });
  return rows[0] ?? null;
}

function nextTransferDate(paidAt: string): string {
  const date = new Date(paidAt);
  if (!Number.isFinite(date.getTime())) {
    throw appError(500, "INVALID_FINANCIAL_RECORD", "paid_at is invalid");
  }
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function redactedCallback(input: Row): Row {
  return {
    merchant_oid: input.merchant_oid,
    status: input.status,
    total_amount: input.total_amount,
    currency: input.currency,
    payment_type: input.payment_type,
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : "Unknown payment error";
  return message.slice(0, 1000);
}

function appError(status: number, code: string, message: string): MarketplaceApplicationError {
  return new MarketplaceApplicationError(status, code, message);
}

function isRecord(value: unknown): value is Row {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
