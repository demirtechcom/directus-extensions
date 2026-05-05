import type { Router } from "express";
import crypto from "crypto";

const SUBSCRIPTION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const CURRENCY_MAP: Record<string, string> = { TRY: "TL", USD: "USD", EUR: "EUR", GBP: "GBP" };

function hmacSha256Base64(key: string, data: string): string {
  return Buffer.from(crypto.createHmac("sha256", key).update(data).digest()).toString("base64");
}

function getClientIp(req: any): string {
  return (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.ip || "127.0.0.1")
    .split(",")[0]
    .trim();
}

export default (router: Router, context: any) => {
  const { env, services, getSchema, database, logger } = context;

  // Plan adına göre atanacak Directus policy ID'si.
  // Yeni paket eklenirse buraya da eklenmeli; UUID'ler env'den okunur.
  const PLAN_POLICY_MAP: Record<string, string> = {
    "Customer Pro": String(env["BUSINESS_POLICY_ID"] || ""),
  };

  if (!env["BUSINESS_POLICY_ID"]) {
    logger.warn("[payments] BUSINESS_POLICY_ID is not set — subscription policy grants will be skipped");
  } else {
    logger.info(`[payments] BUSINESS_POLICY_ID loaded: ${String(env["BUSINESS_POLICY_ID"]).slice(0, 8)}...`);
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

  async function grantPolicyAccess(userId: string, policyId: string) {
    try {
      const existing = await database("directus_access")
        .where({ user: userId, policy: policyId })
        .first();
      if (!existing) {
        await database("directus_access").insert({
          id: crypto.randomUUID(),
          user: userId,
          policy: policyId,
        });
        logger.info(`[payments] directus_access row inserted: user=${userId} policy=${policyId}`);
      } else {
        logger.info(`[payments] directus_access already exists: user=${userId} policy=${policyId}`);
      }
    } catch (err: any) {
      logger.error(`[payments] grantPolicyAccess failed: ${err.message}`);
      throw err;
    }
  }

  async function revokePolicyAccess(userId: string, policyId: string) {
    try {
      await database("directus_access")
        .where({ user: userId, policy: policyId })
        .delete();
      logger.info(`[payments] directus_access row deleted: user=${userId} policy=${policyId}`);
    } catch (err: any) {
      logger.error(`[payments] revokePolicyAccess failed: ${err.message}`);
      throw err;
    }
  }

  async function activateSubscription(
    userId: string,
    planId: number,
    paymentId: number,
    paymentType: string | null,
    cardTokens: { userToken?: string; cardToken?: string },
  ) {
    const schema = await getSchema();
    const paymentsService = new services.ItemsService("payments", { schema, accountability: { admin: true } });
    const usersService = new services.UsersService({ schema, accountability: { admin: true } });
    const plansService = new services.ItemsService("subscription_plans", { schema, accountability: { admin: true } });

    await paymentsService.updateOne(paymentId, {
      payment_status: "success",
      payment_type: paymentType,
      stored_card_user_token: cardTokens.userToken || null,
      stored_card_token: cardTokens.cardToken || null,
    });

    const userUpdate: Record<string, any> = {
      subscription_tier: "pro",
      subscription_expires_at: new Date(Date.now() + SUBSCRIPTION_DURATION_MS).toISOString(),
    };
    if (cardTokens.userToken) userUpdate.stored_card_user_token = cardTokens.userToken;
    if (cardTokens.cardToken) userUpdate.stored_card_token = cardTokens.cardToken;

    await usersService.updateOne(userId, userUpdate);

    const plan = await plansService.readOne(planId, { fields: ["name"] });
    logger.info(`[payments] activateSubscription planId=${planId} planName=${plan?.name}`);
    const targetPolicyId = plan?.name ? PLAN_POLICY_MAP[plan.name] : "";
    if (targetPolicyId) {
      await grantPolicyAccess(userId, targetPolicyId);
    } else {
      logger.warn(`[payments] no policy mapped for plan "${plan?.name}" — check PLAN_POLICY_MAP and BUSINESS_POLICY_ID`);
    }
  }

  async function deactivateSubscription(userId: string, planName: string) {
    const schema = await getSchema();
    const usersService = new services.UsersService({ schema, accountability: { admin: true } });

    await usersService.updateOne(userId, {
      subscription_tier: null,
      subscription_expires_at: null,
    });

    const targetPolicyId = PLAN_POLICY_MAP[planName];
    if (targetPolicyId) {
      await revokePolicyAccess(userId, targetPolicyId);
      logger.info(`[payments] policy revoked userId=${userId} planName=${planName} policy=${targetPolicyId}`);
    }
  }

  async function findPendingPayment(merchantOid: string) {
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
        return res.json({ payment_status: "pending" });
      }

      const payment = await findPendingPayment(merchantOid);
      if (!payment) {
        logger.warn(`[payments] check-status: no payment found for merchant_oid=${merchantOid}`);
        return res.json({ payment_status: "success" });
      }

      logger.info(`[payments] check-status payment found — id=${payment.id} status=${payment.payment_status}`);

      if (payment.payment_status === "pending") {
        await activateSubscription(payment.user_id, payment.plan_id, payment.id, statusRes.odeme_tipi || "card", {});
        logger.info(`[payments] activated via check-status: ${merchantOid}`);
      }

      return res.json({ payment_status: "success" });
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

      const paymentsService = new services.ItemsService("payments", { schema, accountability: { admin: true } });
      const plansService = new services.ItemsService("subscription_plans", { schema, accountability: { admin: true } });
      const lastPayment = await paymentsService.readByQuery({
        filter: { user_id: { _eq: userId }, payment_status: { _eq: "success" } },
        sort: ["-date_created"],
        fields: ["plan_id"],
        limit: 1,
      });

      if (lastPayment.length > 0) {
        const plan = await plansService.readOne(lastPayment[0].plan_id, { fields: ["name"] });
        if (plan?.name) {
          await deactivateSubscription(userId, plan.name);
        }
      }

      return res.json({ success: true });
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

      const payment = await findPendingPayment(merchant_oid);
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
