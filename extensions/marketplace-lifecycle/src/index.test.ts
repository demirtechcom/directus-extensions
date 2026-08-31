import { describe, expect, it } from "bun:test";

import registerMarketplaceLifecycle from "./index";

describe("marketplace lifecycle hook", () => {
  it("runs reconciliation every minute without requiring public HTTP access", async () => {
    let cron = "";
    let handler: (() => Promise<void> | void) | null = null;
    const logs: string[] = [];
    class ItemsService {
      async readByQuery(): Promise<unknown[]> {
        return [];
      }
    }

    registerMarketplaceLifecycle(
      {
        schedule(value, scheduledHandler) {
          cron = value;
          handler = scheduledHandler;
        },
      },
      {
        env: {},
        services: { ItemsService, UsersService: class {} },
        getSchema: async () => ({}),
        database: { transaction: async (run: (trx: unknown) => unknown) => run({}) },
        logger: {
          info: (message: string) => logs.push(message),
          warn: () => undefined,
          error: () => undefined,
        },
      },
    );

    expect(cron).toBe("* * * * *");
    expect(handler).not.toBeNull();
    await handler?.();
    expect(logs[0]).toContain("reconciled=0 refunded=0 submitted=0");
  });
});
