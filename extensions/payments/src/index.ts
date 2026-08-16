import type { Router } from "express";
import crypto from "crypto";

import { registerOrderIntake } from "./order-intake.js";
import {
  buildSubscriptionPayload,
  computeExpiry,
  isPaymentAlreadyApplied,
  resolveDurationDays,
  type SubscriptionRow,
} from "./subscription.js";

const CURRENCY_MAP: Record<string, string> = { TRY: "TL", USD: "USD", EUR: "EUR", GBP: "GBP" };

function hmacSha256Base64(key: string, data: string): string {
  return Buffer.from(crypto.createHmac("sha256", key).update(data).digest()).toString("base64");
}

function getClientIp(req: any): string {
  return (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.ip || "127.0.0.1")
    .split(",")[0]
    .trim();
}

function normalizeId(value: any): number | null {
  const raw = value !== null && typeof value === "object" ? value.id : value;
  const id = Number(raw);
  return Number.isInteger(id) && id > 0 ? id : null;
}

export default (router: Router, context: any) => {
  const { env, services, getSchema, logger, database } = context;

  const BUSINESS_ROLE_ID = String(env["BUSINESS_ROLE_ID"] || "");
  const DEFAULT_ROLE_ID = String(env["SSO_DEFAULT_ROLE_ID"] || "");

  registerOrderIntake(router, context);

  // Logged at error level on purpose: a missing role id means paid users silently
  // keep their free-tier permissions, which is worse than a noisy boot.
  if (BUSINESS_ROLE_ID) {
    logger.info(`[payments] BUSINESS_ROLE_ID loaded: ${BUSINESS_ROLE_ID.slice(0, 8)}...`);
  } else {
    logger.error("[payments] BUSINESS_ROLE_ID is not set — paid users will NOT receive Business access");
  }

  if (DEFAULT_ROLE_ID) {
    logger.info(`[payments] SSO_DEFAULT_ROLE_ID loaded: ${DEFAULT_ROLE_ID.slice(0, 8)}...`);
  } else {
    logger.error("[payments] SSO_DEFAULT_ROLE_ID is not set — cancellations will NOT revert the role");
  }

  // --- Shared helpers ---

  function getPayTRConfig() {
    return {
      merchantId: String(env["PAYTR_MERCHANT_ID"] || ""),
      merchantKey: String(env["PAYTR_MERCHANT_KEY"] || ""),
      merchantSalt: String(env["PAYTR_MERCHANT_SALT"] || ""),
      testMode: String(env["PAYTR_TEST_MODE"] || "0"),
      callbackUrl: String(env["PAYTR_CALLBACK_URL"] || ""),
      okUrl: String(env["PAYTR_OK_URL"] || ""),
      failUrl: String(env["PAYTR_FAIL_URL"] || ""),
      appUrl: String(env["PAYMENTS_APP_URL"] || env["PAYTR_APP_URL"] || "http://localhost:8081"),
    };
  }

  /**
   * Applies a successful payment: entitlement on the user, a paid period on the
   * venue's `subscriptions` row, and the payment marked `success` last.
   *
   * The whole thing runs in one transaction that claims the still-pending
   * payment row with `FOR UPDATE`. Both the provider callback and the client's
   * /check-status poll reach this path for the same payment, and now that a
   * renewal stacks onto the remaining days, activating twice would hand out a
   * second period for free.
   */
  async function activateSubscription(
    userId: string,
    planId: number,
    paymentId: number,
    paymentType: string | null,
    cardTokens: { userToken?: string; cardToken?: string },
  ): Promise<boolean> {
    const schema = await getSchema();

    return database.transaction(async (trx: any) => {
      const claimed = await trx("payments")
        .where({ id: paymentId, payment_status: "pending" })
        .forUpdate()
        .select("id");

      if (claimed.length === 0) {
        logger.info(`[payments] activation skipped, payment already applied: id=${paymentId}`);
        return false;
      }

      const options = { schema, knex: trx, accountability: { admin: true } };
      const paymentsService = new services.ItemsService("payments", options);
      const usersService = new services.UsersService(options);
      const plansService = new services.ItemsService("subscription_plans", options);
      const subscriptionsService = new services.ItemsService("subscriptions", options);

      const user = await usersService.readOne(userId, {
        fields: ["id", "venue_id", "subscription_expires_at"],
      });
      const plan = await plansService.readOne(planId, { fields: ["id", "duration_days"] });

      const durationDays = resolveDurationDays(plan?.duration_days);
      const nowMs = Date.now();
      const expiry = computeExpiry(user?.subscription_expires_at, durationDays, nowMs);

      // The role goes through UsersService rather than a raw Knex update so that
      // Directus invalidates its own permission caches. Directus only applies
      // role-level policies to JWT-authenticated requests, so the role — not a
      // user-level directus_access row — is what actually grants the entitlement.
      const userUpdate: Record<string, any> = {
        subscription_tier: "pro",
        subscription_expires_at: expiry.toISOString(),
      };
      if (BUSINESS_ROLE_ID) {
        userUpdate.role = BUSINESS_ROLE_ID;
      } else {
        logger.error(`[payments] BUSINESS_ROLE_ID missing — activating without Business role: user=${userId}`);
      }
      if (cardTokens.userToken) userUpdate.stored_card_user_token = cardTokens.userToken;
      if (cardTokens.cardToken) userUpdate.stored_card_token = cardTokens.cardToken;

      await usersService.updateOne(userId, userUpdate);

      if (userUpdate.role) {
        logger.info(`[payments] role updated to Business: user=${userId}`);
      }

      const venueId = normalizeId(user?.venue_id);
      if (venueId === null) {
        // Businesses can pay before their venue record exists, so this is not an
        // error. The user-level entitlement above is what gates the app; the
        // venue row gets its period on the next payment after onboarding.
        logger.warn(`[payments] user=${userId} has no venue — subscription row not written`);
      } else {
        const rows: SubscriptionRow[] = await subscriptionsService.readByQuery({
          filter: { venue_id: { _eq: venueId } },
          fields: ["id", "start_date", "end_date", "last_payment_id"],
          sort: ["-end_date"],
          limit: 1,
        });
        const existing = rows[0] ?? null;

        if (isPaymentAlreadyApplied(existing, paymentId)) {
          logger.info(`[payments] subscription already carries payment=${paymentId}`);
        } else {
          const payload = buildSubscriptionPayload(existing, planId, paymentId, expiry, nowMs);
          if (existing) {
            await subscriptionsService.updateOne(existing.id, payload);
          } else {
            await subscriptionsService.createOne({ venue_id: venueId, ...payload });
          }
          logger.info(`[payments] subscription period venue=${venueId} ends ${payload.end_date}`);
        }
      }

      // Marked success last. While the row is still `pending`, both the webhook
      // retry and /check-status will re-run this function; flipping it first
      // would make any failure above permanent, since both paths skip
      // already-processed payments.
      await paymentsService.updateOne(paymentId, {
        payment_status: "success",
        payment_type: paymentType,
        stored_card_user_token: cardTokens.userToken || null,
        stored_card_token: cardTokens.cardToken || null,
      });

      logger.info(
        `[payments] activateSubscription complete planId=${planId} userId=${userId} expires=${expiry.toISOString()}`,
      );
      return true;
    });
  }

  async function deactivateSubscription(userId: string) {
    const schema = await getSchema();
    const usersService = new services.UsersService({ schema, accountability: { admin: true } });

    const userUpdate: Record<string, any> = {
      subscription_tier: null,
      subscription_expires_at: null,
    };
    if (DEFAULT_ROLE_ID) {
      userUpdate.role = DEFAULT_ROLE_ID;
    } else {
      logger.error(`[payments] SSO_DEFAULT_ROLE_ID missing — subscription cancelled but role left as Business: user=${userId}`);
    }

    await usersService.updateOne(userId, userUpdate);

    if (userUpdate.role) {
      logger.info(`[payments] role reverted to default: user=${userId}`);
    }
  }

  async function findPayment(merchantOid: string) {
    const schema = await getSchema();
    const paymentsService = new services.ItemsService("payments", { schema, accountability: { admin: true } });

    const payments = await paymentsService.readByQuery({
      filter: { merchant_oid: { _eq: merchantOid } },
      fields: ["id", "user_id", "plan_id", "payment_status"],
      limit: 1,
    });

    return payments[0] || null;
  }

  // ─── GET TOKEN ───────────────────────────────────────────────
  router.post("/get-token", async (req: any, res: any) => {
    try {
      const userId = req.accountability?.user;
      if (!userId) return res.status(401).json({ error: "Authentication required" });

      const planId = req.body?.plan_id;
      if (!planId) return res.status(400).json({ error: "plan_id is required" });

      const schema = await getSchema();
      const usersService = new services.UsersService({ schema, accountability: { admin: true } });
      const plansService = new services.ItemsService("subscription_plans", { schema, accountability: { admin: true } });

      const user = await usersService.readOne(userId, { fields: ["email", "first_name", "last_name", "phone"] });
      const plan = await plansService.readOne(planId, { fields: ["name", "price_minor", "currency"] });

      if (!plan?.price_minor) {
        return res.status(400).json({ error: "Invalid plan" });
      }

      const config = getPayTRConfig();
      if (!config.merchantId || !config.merchantKey || !config.merchantSalt) {
        logger.error("[payments] Missing merchant credentials — check PAYTR_MERCHANT_ID/KEY/SALT env vars");
        return res.status(500).json({ error: "Payment service not configured" });
      }

      const userIp = getClientIp(req);
      const merchantOid = "DLVR" + userId.replace(/-/g, "").slice(0, 8) + Date.now();
      const paymentAmount = plan.price_minor;
      const currency = CURRENCY_MAP[plan.currency] || "TL";

      const priceStr = (paymentAmount / 100).toFixed(2);
      const userBasket = Buffer.from(JSON.stringify([[plan.name, priceStr, 1]])).toString("base64");
      const userName = [user.first_name, user.last_name].filter(Boolean).join(" ") || "Kullanici";

      const hashStr =
        config.merchantId + userIp + merchantOid + user.email + paymentAmount +
        userBasket + "1" + "0" + currency + config.testMode + config.merchantSalt;
      const paytrToken = hmacSha256Base64(config.merchantKey, hashStr);

      const tokenRes = await fetch("https://www.paytr.com/odeme/api/get-token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          merchant_id: config.merchantId,
          user_ip: userIp,
          merchant_oid: merchantOid,
          email: user.email,
          payment_amount: String(paymentAmount),
          paytr_token: paytrToken,
          user_basket: userBasket,
          debug_on: config.testMode,
          no_installment: "1",
          max_installment: "0",
          currency,
          test_mode: config.testMode,
          user_name: userName,
          user_address: "Turkiye",
          user_phone: user.phone || "05000000000",
          merchant_ok_url: config.okUrl,
          merchant_fail_url: config.failUrl,
          merchant_notify_url: config.callbackUrl,
          lang: "tr",
        }).toString(),
      }).then((r) => r.json() as Promise<{ status: string; token?: string; reason?: string }>);

      if (tokenRes.status !== "success") {
        logger.error(`[payments] provider token error: ${tokenRes.reason}`);
        return res.status(400).json({ error: "Payment provider error" });
      }

      const paymentsService = new services.ItemsService("payments", { schema, accountability: { admin: true } });
      await paymentsService.createOne({
        user_id: userId,
        plan_id: planId,
        merchant_oid: merchantOid,
        payment_amount: paymentAmount,
        payment_status: "pending",
        provider: "paytr",
        currency: plan.currency || "TRY",
      });

      return res.json({ token: tokenRes.token, merchant_oid: merchantOid });
    } catch (err: any) {
      logger.error(`[payments] get-token error: ${err.message}\n${err.stack}`);
      return res.status(500).json({ error: "Payment request failed" });
    }
  });

  // ─── CHECK STATUS ────────────────────────────────────────────
  router.get("/check-status", async (req: any, res: any) => {
    try {
      const userId = req.accountability?.user;
      if (!userId) return res.status(401).json({ error: "Authentication required" });

      const merchantOid = req.query.merchant_oid;
      if (!merchantOid) return res.status(400).json({ error: "merchant_oid is required" });

      const payment = await findPayment(merchantOid);
      if (!payment) {
        logger.warn(`[payments] check-status: no payment found for merchant_oid=${merchantOid}`);
        return res.status(404).json({ error: "Payment not found" });
      }
      if (payment.user_id !== userId) {
        logger.warn(`[payments] check-status: user=${userId} requested payment owned by user=${payment.user_id}`);
        return res.status(403).json({ error: "Forbidden" });
      }

      const config = getPayTRConfig();
      const paytrToken = hmacSha256Base64(
        config.merchantKey,
        config.merchantId + merchantOid + config.merchantSalt,
      );

      const statusRes = await fetch("https://www.paytr.com/odeme/durum-sorgu", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          merchant_id: config.merchantId,
          merchant_oid: merchantOid,
          merchant_key: config.merchantKey,
          merchant_salt: config.merchantSalt,
          paytr_token: paytrToken,
        }).toString(),
      }).then((r) => r.json() as Promise<any>);

      logger.info(`[payments] check-status paytr response: status=${statusRes.status} odeme_tipi=${statusRes.odeme_tipi}`);

      if (statusRes.status !== "success") {
        return res.json({ payment_status: "pending", role_updated: false });
      }

      logger.info(`[payments] check-status payment found — id=${payment.id} status=${payment.payment_status}`);

      if (payment.payment_status === "pending") {
        await activateSubscription(payment.user_id, payment.plan_id, payment.id, statusRes.odeme_tipi || "card", {});
        logger.info(`[payments] activated via check-status: ${merchantOid}`);
      }

      // The role lives in the access-token claims minted by sso-exchange, so the
      // client must call /sso-exchange/refresh before the new permissions apply.
      return res.json({ payment_status: "success", role_updated: Boolean(BUSINESS_ROLE_ID) });
    } catch (err: any) {
      logger.error(`[payments] check-status error: ${err.message}\n${err.stack}`);
      return res.status(500).json({ error: "Status check failed" });
    }
  });

  // ─── CANCEL ──────────────────────────────────────────────────
  router.post("/cancel", async (req: any, res: any) => {
    try {
      const userId = req.accountability?.user;
      if (!userId) return res.status(401).json({ error: "Authentication required" });

      const schema = await getSchema();
      const usersService = new services.UsersService({ schema, accountability: { admin: true } });
      const user = await usersService.readOne(userId, { fields: ["subscription_tier"] });

      if (!user?.subscription_tier) {
        return res.status(400).json({ error: "No active subscription" });
      }

      await deactivateSubscription(userId);

      return res.json({ success: true, role_updated: Boolean(DEFAULT_ROLE_ID) });
    } catch (err: any) {
      logger.error(`[payments] cancel error: ${err.message}\n${err.stack}`);
      return res.status(500).json({ error: "Cancellation failed" });
    }
  });

  // ─── CALLBACK ────────────────────────────────────────────────
  router.post("/callback", async (req: any, res: any) => {
    try {
      const body = req.body || {};
      logger.info(`[payments] callback received — body keys: ${Object.keys(body).join(", ")}`);

      const { merchant_oid, status, total_amount, hash, payment_type, failed_reason_msg } = body;

      if (!merchant_oid || !status || !hash) {
        logger.warn(`[payments] callback missing required fields — merchant_oid=${merchant_oid} status=${status} hash=${!!hash}`);
        return res.send("OK");
      }

      logger.info(`[payments] callback merchant_oid=${merchant_oid} status=${status} total_amount=${total_amount}`);

      const config = getPayTRConfig();
      const expectedHash = hmacSha256Base64(
        config.merchantKey,
        merchant_oid + config.merchantSalt + status + total_amount,
      );

      if (hash !== expectedHash) {
        logger.error(`[payments] hash mismatch for ${merchant_oid} — expected=${expectedHash} got=${hash}`);
        return res.send("OK");
      }

      logger.info(`[payments] hash verified for ${merchant_oid}`);

      const payment = await findPayment(merchant_oid);
      if (!payment) {
        logger.warn(`[payments] no payment record found for merchant_oid=${merchant_oid}`);
        return res.send("OK");
      }
      if (payment.payment_status !== "pending") {
        logger.info(`[payments] payment already processed — merchant_oid=${merchant_oid} status=${payment.payment_status}`);
        return res.send("OK");
      }

      logger.info(`[payments] payment found — id=${payment.id} user_id=${payment.user_id} plan_id=${payment.plan_id}`);

      if (status === "success") {
        await activateSubscription(payment.user_id, payment.plan_id, payment.id, payment_type || null, {
          userToken: body.utoken,
          cardToken: body.ctoken,
        });
        logger.info(`[payments] activation complete for merchant_oid=${merchant_oid}`);
      } else {
        const schema = await getSchema();
        const paymentsService = new services.ItemsService("payments", { schema, accountability: { admin: true } });
        await paymentsService.updateOne(payment.id, {
          payment_status: "failed",
          failed_reason: failed_reason_msg || "Payment failed",
        });
        logger.warn(`[payments] payment failed merchant_oid=${merchant_oid} reason=${failed_reason_msg}`);
      }

      return res.send("OK");
    } catch (err: any) {
      // Always 200 OK: PayTR retries on anything else, and the payment row is left
      // `pending` above, so a retry re-runs activation instead of skipping it.
      logger.error(`[payments] callback error: ${err.message}\n${err.stack}`);
      return res.send("OK");
    }
  });

  // ─── REDIRECT ────────────────────────────────────────────────
  router.get("/ok", (_req: any, res: any) => {
    return res.redirect(`${getPayTRConfig().appUrl}/paywall?status=ok`);
  });

  router.get("/fail", (_req: any, res: any) => {
    return res.redirect(`${getPayTRConfig().appUrl}/paywall?status=fail`);
  });
};
