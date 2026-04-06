import type { Router } from "express";
import crypto from "crypto";

export default (router: Router, context: any) => {
  const { env, services, getSchema } = context;

  // ─── GET TOKEN ───────────────────────────────────────────────
  router.post("/get-token", async (req: any, res: any) => {
    try {
      const userId = req.accountability?.user;
      if (!userId) return res.status(401).json({ error: "Authentication required" });

      const planId = req.body?.plan_id;
      if (!planId) return res.status(400).json({ error: "plan_id is required" });

      const schema = await getSchema();
      const usersService = new services.UsersService({ schema, accountability: { admin: true } });
      const itemsService = new services.ItemsService("subscription_plans", { schema, accountability: { admin: true } });

      const user = await usersService.readOne(userId, { fields: ["email", "first_name", "last_name"] });
      const plan = await itemsService.readOne(planId, { fields: ["name", "paytr_price_kurus"] });

      if (!plan?.paytr_price_kurus) {
        return res.status(400).json({ error: "Invalid plan" });
      }

      const merchantId = String(env["PAYTR_MERCHANT_ID"] || "");
      const merchantKey = String(env["PAYTR_MERCHANT_KEY"] || "");
      const merchantSalt = String(env["PAYTR_MERCHANT_SALT"] || "");
      const testMode = String(env["PAYTR_TEST_MODE"] || "0");
      const callbackUrl = String(env["PAYTR_CALLBACK_URL"] || "");
      const okUrl = String(env["PAYTR_OK_URL"] || "");
      const failUrl = String(env["PAYTR_FAIL_URL"] || "");

      if (!merchantId || !merchantKey || !merchantSalt) {
        console.error("[paytr] Missing PAYTR_MERCHANT_ID, PAYTR_MERCHANT_KEY, or PAYTR_MERCHANT_SALT");
        return res.status(500).json({ error: "Payment service not configured" });
      }

      const userIp = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.ip || "127.0.0.1")
        .split(",")[0]
        .trim();
      const merchantOid = "DLVR" + userId.replace(/-/g, "").slice(0, 8) + Date.now();
      const paymentAmount = plan.paytr_price_kurus;
      const currency = "TL";
      const noInstallment = 1;
      const maxInstallment = 0;

      const priceStr = (paymentAmount / 100).toFixed(2);
      const userBasket = Buffer.from(
        JSON.stringify([[plan.name, priceStr, 1]]),
      ).toString("base64");

      // Build HMAC-SHA256 token
      const hashStr =
        merchantId +
        userIp +
        merchantOid +
        user.email +
        paymentAmount +
        userBasket +
        noInstallment +
        maxInstallment +
        currency +
        testMode +
        merchantSalt;
      const paytrToken = Buffer.from(
        crypto.createHmac("sha256", merchantKey).update(hashStr).digest(),
      ).toString("base64");

      const userName = [user.first_name, user.last_name].filter(Boolean).join(" ") || "Kullanici";

      // Request iframe token from PayTR
      const params = new URLSearchParams({
        merchant_id: merchantId,
        user_ip: userIp,
        merchant_oid: merchantOid,
        email: user.email,
        payment_amount: String(paymentAmount),
        paytr_token: paytrToken,
        user_basket: userBasket,
        debug_on: testMode,
        no_installment: String(noInstallment),
        max_installment: String(maxInstallment),
        currency,
        test_mode: testMode,
        user_name: userName,
        user_address: "N/A",
        user_phone: "N/A",
        merchant_ok_url: okUrl,
        merchant_fail_url: failUrl,
        merchant_notify_url: callbackUrl,
        lang: "tr",
      });

      const tokenRes = await fetch("https://www.paytr.com/odeme/api/get-token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
      }).then((r) => r.json() as Promise<{ status: string; token?: string; reason?: string }>);

      if (tokenRes.status !== "success") {
        console.error("[paytr] PayTR token error:", tokenRes.reason);
        return res.status(400).json({ error: "Payment provider error" });
      }

      // Create pending payment record
      const paymentsService = new services.ItemsService("paytr_payments", {
        schema,
        accountability: { admin: true },
      });
      await paymentsService.createOne({
        user_id: userId,
        plan_id: planId,
        merchant_oid: merchantOid,
        payment_amount: paymentAmount,
        payment_status: "pending",
      });

      return res.json({ token: tokenRes.token, merchant_oid: merchantOid });
    } catch (err: any) {
      console.error("[paytr] get-token error:", err.message);
      return res.status(500).json({ error: "Payment request failed" });
    }
  });

  // ─── CALLBACK ────────────────────────────────────────────────
  router.post("/callback", async (req: any, res: any) => {
    try {
      const body = req.body || {};
      const { merchant_oid, status, total_amount, hash, payment_type, failed_reason_msg } = body;

      if (!merchant_oid || !status || !hash) return res.send("OK");

      const merchantKey = String(env["PAYTR_MERCHANT_KEY"] || "");
      const merchantSalt = String(env["PAYTR_MERCHANT_SALT"] || "");

      // Verify hash
      const expectedHash = Buffer.from(
        crypto
          .createHmac("sha256", merchantKey)
          .update(merchant_oid + merchantSalt + status + total_amount)
          .digest(),
      ).toString("base64");

      if (hash !== expectedHash) {
        console.error("[paytr] Hash mismatch for", merchant_oid);
        return res.send("OK");
      }

      const schema = await getSchema();
      const paymentsService = new services.ItemsService("paytr_payments", {
        schema,
        accountability: { admin: true },
      });
      const usersService = new services.UsersService({
        schema,
        accountability: { admin: true },
      });

      // Find payment record
      const payments = await paymentsService.readByQuery({
        filter: { merchant_oid: { _eq: merchant_oid } },
        fields: ["id", "user_id", "plan_id", "payment_status"],
        limit: 1,
      });

      const payment = payments[0];
      if (!payment || payment.payment_status !== "pending") return res.send("OK");

      if (status === "success") {
        // Update payment record with card tokens
        await paymentsService.updateOne(payment.id, {
          payment_status: "success",
          payment_type: payment_type || null,
          utoken: body.utoken || null,
          ctoken: body.ctoken || null,
        });

        // Store card tokens on user for recurring billing
        const userUpdate: Record<string, any> = {
          subscription_tier: "pro",
          subscription_expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        };
        if (body.utoken) userUpdate.paytr_utoken = body.utoken;
        if (body.ctoken) userUpdate.paytr_ctoken = body.ctoken;

        await usersService.updateOne(payment.user_id, userUpdate);

        // Update subscription record if exists
        const subsService = new services.ItemsService("subscriptions", {
          schema,
          accountability: { admin: true },
        });
        const subs = await subsService.readByQuery({
          filter: {
            _and: [
              { venue_id: { user_created: { _eq: payment.user_id } } },
              { subscription_status: { _in: ["active", "trial"] } },
            ],
          },
          fields: ["id"],
          limit: 1,
        });

        if (subs[0]) {
          const endDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
            .toISOString()
            .split("T")[0];
          await subsService.updateOne(subs[0].id, {
            subscription_status: "active",
            plan_id: payment.plan_id,
            end_date: endDate,
            auto_renew: true,
          });
        }

        console.log("[paytr] Payment success:", merchant_oid);
      } else {
        await paymentsService.updateOne(payment.id, {
          payment_status: "failed",
          failed_reason: failed_reason_msg || "Payment failed",
        });
        console.log("[paytr] Payment failed:", merchant_oid, failed_reason_msg);
      }

      return res.send("OK");
    } catch (err: any) {
      console.error("[paytr] callback error:", err.message);
      return res.send("OK");
    }
  });

  // ─── REDIRECT ────────────────────────────────────────────────
  // GET /paytr/ok  — PayTR redirects user here after successful payment
  // GET /paytr/fail — PayTR redirects user here after failed payment
  router.get("/ok", (_req: any, res: any) => {
    const appUrl = String(env["PAYTR_APP_URL"] || "http://localhost:8081");
    return res.redirect(`${appUrl}/paywall?status=ok`);
  });

  router.get("/fail", (_req: any, res: any) => {
    const appUrl = String(env["PAYTR_APP_URL"] || "http://localhost:8081");
    return res.redirect(`${appUrl}/paywall?status=fail`);
  });
};
