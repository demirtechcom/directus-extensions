import { createMarketplaceApplication } from "../../payments/src/marketplace-application.js";

const DEFAULT_CRON = "* * * * *";

interface HookEvents {
  schedule(cron: string, handler: () => Promise<void> | void): void;
}

export default ({ schedule }: HookEvents, context: any): void => {
  const cron = String(context.env["MARKETPLACE_LIFECYCLE_CRON"] || DEFAULT_CRON);
  const application = createMarketplaceApplication(context);

  schedule(cron, async () => {
    const result = await application.runLifecycle({});
    context.logger.info(
      `[payments] marketplace lifecycle reconciled=${String(result.reconciled)} refunded=${String(result.refunded)} submitted=${String(result.submitted)}`,
    );
  });
};
