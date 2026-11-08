/**
 * The editor's half: publishing an approved submission into `zest_province_menus`, and undoing it.
 *
 * Driven by the status field an editor sets in the Directus admin, not by a Flow button, so there
 * is nothing to wire up after deploying: set a pending row to `approved` and it is published (or
 * marked `publish_failed` with the reason); set a published row to `rolled_back` and every row it
 * created is removed and every row it replaced is restored.
 *
 * A published menu applies to the whole province - `zest_province_menus` has no dorm column, and
 * the app shows one menu per province.
 *
 * Duplicates: the existing (province, date, meal) row wins unless the editor sets
 * `publish_mode = replace` before approving. Each skip and each replacement is written to
 * `publish_log`, which is also what makes the rollback exact.
 */

import { calorieRange, dateColumn, normalizeDays, parseJson, STATUS, T } from "./shared";

type MealType = "BREAKFAST" | "DINNER";

export interface PublishLog {
  mode: "skip" | "replace";
  created: (number | string)[];
  replaced: Record<string, unknown>[];
  skipped: { date: string; type: MealType }[];
  published_at?: string;
  rolled_back_at?: string;
  error?: string;
}

export async function publish(
  key: string,
  ctx: { database: any; services: any; getSchema: () => Promise<any>; env: Record<string, any> },
): Promise<PublishLog> {
  const { database, services, getSchema, env } = ctx;
  const row = await database(T.submissions).where({ id: key }).first();
  if (!row || row.status !== STATUS.approved) {
    throw new Error("Submission is not approved");
  }
  const provinceId = row.province_id == null ? Number.NaN : Number(row.province_id);
  if (!Number.isInteger(provinceId)) throw new Error("Submission has no province");
  const days = normalizeDays(parseJson(row.days, []));
  if (days.length === 0) throw new Error("Submission has no days");

  const mode: PublishLog["mode"] = row.publish_mode === "replace" ? "replace" : "skip";
  const log: PublishLog = { mode, created: [], replaced: [], skipped: [] };
  const schema = await getSchema();

  await database.transaction(async (trx: any) => {
    // ItemsService rather than raw inserts so Directus fills special fields and records activity,
    // the same as the import script going through REST would.
    const menus = new services.ItemsService(T.provinceMenus, {
      schema,
      knex: trx,
      accountability: null,
    });
    for (const day of days) {
      for (const [type, items] of [
        ["BREAKFAST", day.breakfast],
        ["DINNER", day.dinner],
      ] as [MealType, string[]][]) {
        if (items.length === 0) continue;
        const existing = await trx(T.provinceMenus)
          .where({ province_id: provinceId, date: day.date, type })
          .select("*");
        if (existing.length > 0) {
          if (mode === "skip") {
            log.skipped.push({ date: day.date, type });
            continue;
          }
          log.replaced.push(...existing);
          await menus.deleteMany(existing.map((r: any) => r.id));
        }
        const id = await menus.createOne({
          province_id: provinceId,
          date: day.date,
          type,
          items,
          calorie_range: calorieRange(env, type),
        });
        log.created.push(id);
      }
    }
  });

  log.published_at = new Date().toISOString();
  return log;
}

export async function rollback(
  key: string,
  ctx: { database: any; services: any; getSchema: () => Promise<any> },
): Promise<PublishLog> {
  const { database, services, getSchema } = ctx;
  const row = await database(T.submissions).where({ id: key }).first();
  const log = parseJson<PublishLog | null>(row?.publish_log, null);
  if (!log || !Array.isArray(log.created)) throw new Error("Nothing was published");
  if (log.rolled_back_at) return log;
  const schema = await getSchema();

  await database.transaction(async (trx: any) => {
    const menus = new services.ItemsService(T.provinceMenus, {
      schema,
      knex: trx,
      accountability: null,
    });
    if (log.created.length > 0) await menus.deleteMany(log.created);
    for (const original of log.replaced) {
      // Restored with its original id, so anything that referenced the old row still resolves.
      await menus.createOne({
        ...original,
        date: dateColumn((original as any).date) ?? (original as any).date,
        items: parseJson((original as any).items, []),
        calorie_range: parseJson((original as any).calorie_range, null),
      });
    }
  });

  return { ...log, rolled_back_at: new Date().toISOString() };
}

export default ({ action }: any, context: any) => {
  const { database, logger } = context;

  async function setResult(key: string, status: string, log: Partial<PublishLog>) {
    // Raw update, not ItemsService: going through the service would fire this same hook again.
    await database(T.submissions)
      .where({ id: key })
      .update({ status, publish_log: JSON.stringify(log), date_updated: new Date() });
  }

  action(`${T.submissions}.items.update`, async ({ keys, payload }: any) => {
    const status = payload?.status;
    if (status !== STATUS.approved && status !== STATUS.rolledBack) return;

    for (const key of keys as string[]) {
      if (status === STATUS.approved) {
        try {
          const log = await publish(key, context);
          await setResult(key, STATUS.published, log);
          logger.info(
            `[unifit-menu] published ${key}: ${log.created.length} created, ${log.skipped.length} skipped, ${log.replaced.length} replaced`,
          );
        } catch (error) {
          const message = (error as Error)?.message ?? String(error);
          logger.error(`[unifit-menu] publish ${key} failed: ${message}`);
          await setResult(key, STATUS.publishFailed, { error: message }).catch(() => {});
        }
      } else {
        try {
          const log = await rollback(key, context);
          await setResult(key, STATUS.rolledBack, log);
          logger.info(`[unifit-menu] rolled back ${key}`);
        } catch (error) {
          const message = (error as Error)?.message ?? String(error);
          logger.error(`[unifit-menu] rollback ${key} failed: ${message}`);
          const row = await database(T.submissions).where({ id: key }).first();
          const previous = parseJson<Record<string, unknown>>(row?.publish_log, {});
          await setResult(key, STATUS.publishFailed, { ...previous, error: `rollback: ${message}` }).catch(
            () => {},
          );
        }
      }
    }
  });
};
