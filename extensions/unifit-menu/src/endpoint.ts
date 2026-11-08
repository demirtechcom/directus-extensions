/**
 * `/unifit-menu` - the student's half of a KYK menu submission.
 *
 *   POST /submissions              { file_ids }                  -> { id, status, ... }
 *   GET  /submissions/:id                                        -> the row, as the app shows it
 *   POST /submissions/:id/confirm  { province_id, dorm, days, notes }
 *
 * The app talks to this endpoint and never to the collection. The app role has no permission on
 * `zest_menu_submissions` at all: the status lifecycle, the daily limit and "this file is yours"
 * are rules a client must not be able to argue with, and Directus permissions cannot express the
 * limit. The caller's id always comes from `req.accountability`, never from a body field.
 *
 * Extraction is fire-and-forget after the row is written, and the app polls. A month-long menu on
 * Opus can take a minute, and a synchronous request that long dies at a proxy timeout with the
 * work done and nowhere to put the answer.
 */

import { randomUUID } from "node:crypto";
import type { Request, Response, Router } from "express";

import { buildContent, ExtractionError, extractMenu, type SourceFile } from "./extract";
import {
  CONFIRMABLE,
  COUNTED_STATUSES,
  InputError,
  isIsoDate,
  istanbulDayStart,
  MAX_DORM_LENGTH,
  MAX_FILES,
  MAX_NOTES_LENGTH,
  matchProvince,
  normalizeDays,
  parseJson,
  dateColumn,
  STATUS,
  T,
  UUID_RE,
} from "./shared";

const DEFAULT_DAILY_LIMIT = 5;

/** How long an `extracting` row counts against the limit before it is presumed abandoned. */
const IN_FLIGHT_MS = 10 * 60 * 1000;

const JPEG_RENDITION = {
  transformationParams: {
    format: "jpg",
    width: 2400,
    height: 2400,
    fit: "inside",
    withoutEnlargement: true,
    quality: 85,
  },
};

/** Injectable so tests can prove the limit runs before money is spent. */
export interface EndpointDeps {
  extractMenu: typeof extractMenu;
  buildContent: typeof buildContent;
  now: () => Date;
}

const REAL_DEPS: EndpointDeps = { extractMenu, buildContent, now: () => new Date() };

async function streamToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer | string>) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

export default (router: Router, context: any, deps: EndpointDeps = REAL_DEPS) => {
  const { services, getSchema, database, env, logger } = context;

  const apiKey: string = env.ANTHROPIC_API_KEY ?? "";
  if (!apiKey) {
    logger.warn("[unifit-menu] ANTHROPIC_API_KEY is not set - every extraction will fail");
  }
  const parsedLimit = Number(env.UNIFIT_MENU_DAILY_LIMIT);
  const dailyLimit =
    Number.isInteger(parsedLimit) && parsedLimit >= 0 ? parsedLimit : DEFAULT_DAILY_LIMIT;

  function userId(req: Request): string | null {
    const id = (req as any).accountability?.user;
    return typeof id === "string" && UUID_RE.test(id) ? id : null;
  }

  function fail(res: Response, error: unknown, where: string) {
    if (error instanceof InputError) {
      return res.status(error.status).json({
        errors: [{ message: error.message, extensions: { code: error.code ?? "INVALID_INPUT" } }],
      });
    }
    logger.error(`[unifit-menu] ${where}: ${(error as Error)?.message ?? error}`);
    return res.status(500).json({ errors: [{ message: "Internal error" }] });
  }

  function unauthorized(res: Response) {
    return res.status(401).json({ errors: [{ message: "Unauthorized" }] });
  }

  async function usedToday(user: string): Promise<number> {
    const now = deps.now();
    const since = istanbulDayStart(now);
    const counted = await database(T.submissions)
      .where("user_created", user)
      .where("date_created", ">=", since)
      .whereIn("status", COUNTED_STATUSES)
      .count({ n: "*" })
      .first();
    // In-flight extractions count too: otherwise ten parallel uploads would all see zero and all
    // run. Only recent ones, though - a row whose pod was scaled away mid-call stays `extracting`
    // forever, and must not eat the student's allowance for the rest of the day.
    const inFlight = await database(T.submissions)
      .where("user_created", user)
      .where("date_created", ">=", new Date(Math.max(since.getTime(), now.getTime() - IN_FLIGHT_MS)))
      .where("status", STATUS.extracting)
      .count({ n: "*" })
      .first();
    return Number(counted?.n ?? 0) + Number(inFlight?.n ?? 0);
  }

  async function readFile(id: string, asJpeg: boolean): Promise<Buffer> {
    const { AssetsService } = services;
    const schema = await getSchema();
    // accountability: null is Directus's system context. The ownership check already happened in
    // POST /submissions; the file folder permissions are written for the app, not for this.
    const assets = new AssetsService({ schema, knex: database, accountability: null });
    const { stream } = await assets.getAsset(id, asJpeg ? JPEG_RENDITION : undefined);
    return streamToBuffer(stream);
  }

  async function runExtraction(id: string, files: SourceFile[]): Promise<void> {
    const startedAt = Date.now();
    try {
      const built = await deps.buildContent(files, readFile);
      const today = deps.now().toISOString().slice(0, 10);
      const result = await deps.extractMenu(apiKey, built.blocks, today);
      const { extraction } = result;
      if (extraction.days.length === 0) {
        throw new ExtractionError("No menu days found in the files", {
          problems: extraction.problems,
          skipped: built.skipped,
        });
      }
      const provinces = await database(T.provinces).select("id", "name");
      const provinceId =
        matchProvince(extraction.province, provinces) ?? matchProvince(extraction.dorm, provinces);
      // Only from `extracting`: if the user gave up waiting and confirmed by hand, their table
      // stands and this late answer is dropped.
      await database(T.submissions)
        .where({ id, status: STATUS.extracting })
        .update({
          status: STATUS.extracted,
          extracted: JSON.stringify(extraction),
          days: JSON.stringify(extraction.days),
          province_id: provinceId,
          dorm: extraction.dorm?.slice(0, MAX_DORM_LENGTH) ?? null,
          period_start: extraction.days[0]!.date,
          period_end: extraction.days[extraction.days.length - 1]!.date,
          extract_meta: JSON.stringify({
            model: result.model,
            usage: result.usage,
            used_files: built.used,
            skipped: built.skipped,
            ms: Date.now() - startedAt,
          }),
          date_updated: deps.now(),
        });
    } catch (error) {
      const meta = error instanceof ExtractionError ? error.meta : {};
      logger.warn(`[unifit-menu] extraction ${id} failed: ${(error as Error)?.message ?? error}`);
      await database(T.submissions)
        .where({ id, status: STATUS.extracting })
        .update({
          status: STATUS.extractFailed,
          extract_meta: JSON.stringify({
            ...meta,
            error: (error as Error)?.message ?? String(error),
            ms: Date.now() - startedAt,
          }),
          date_updated: deps.now(),
        })
        .catch((e: unknown) =>
          logger.error(`[unifit-menu] could not mark ${id} failed: ${(e as Error)?.message}`),
        );
    }
  }

  async function ownRow(id: string, user: string) {
    if (!UUID_RE.test(id)) throw new InputError(404, "Not found", "NOT_FOUND");
    const row = await database(T.submissions).where({ id, user_created: user }).first();
    if (!row) throw new InputError(404, "Not found", "NOT_FOUND");
    return row;
  }

  function present(row: any) {
    const extracted = parseJson<any>(row.extracted, null);
    return {
      id: row.id,
      status: row.status,
      province_id: row.province_id ?? null,
      dorm: row.dorm ?? null,
      period_start: dateColumn(row.period_start),
      period_end: dateColumn(row.period_end),
      days: normalizeDays(parseJson(row.days, [])),
      confidence: extracted?.confidence ?? null,
      problems: Array.isArray(extracted?.problems) ? extracted.problems : [],
    };
  }

  router.post("/submissions", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    try {
      const raw = req.body?.file_ids;
      if (
        !Array.isArray(raw) ||
        raw.length === 0 ||
        raw.length > MAX_FILES ||
        raw.some((id) => typeof id !== "string" || !UUID_RE.test(id)) ||
        new Set(raw).size !== raw.length
      ) {
        throw new InputError(400, `file_ids must be 1-${MAX_FILES} distinct file ids`, "INVALID_FILES");
      }
      const fileIds = raw as string[];

      // Only the caller's own uploads. Without this, any signed-in user could have the server read
      // - and send to a third party - a file someone else uploaded, by guessing or leaking its id.
      const files: SourceFile[] = await database("directus_files")
        .whereIn("id", fileIds)
        .andWhere("uploaded_by", user)
        .select("id", "type", "filename_download");
      if (files.length !== fileIds.length) {
        throw new InputError(400, "Unknown file", "INVALID_FILES");
      }
      const ordered = fileIds.map((id) => files.find((f) => f.id === id)!);

      const used = await usedToday(user);
      const limitReached = used >= dailyLimit;
      const id = randomUUID();
      const now = deps.now();
      const status = limitReached ? STATUS.limitReached : STATUS.extracting;

      await database.transaction(async (trx: any) => {
        await trx(T.submissions).insert({
          id,
          user_created: user,
          date_created: now,
          date_updated: now,
          status,
        });
        await trx(T.submissionFiles).insert(
          fileIds.map((fileId) => ({ zest_menu_submissions_id: id, directus_files_id: fileId })),
        );
      });

      if (!limitReached) void runExtraction(id, ordered);

      return res.status(201).json({
        data: { id, status, daily_limit: dailyLimit, used_today: used + (limitReached ? 0 : 1) },
      });
    } catch (error) {
      return fail(res, error, "create submission");
    }
  });

  router.get("/submissions/:id", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    try {
      const row = await ownRow(String(req.params.id), user);
      return res.json({ data: present(row) });
    } catch (error) {
      return fail(res, error, "read submission");
    }
  });

  router.post("/submissions/:id/confirm", async (req: Request, res: Response) => {
    const user = userId(req);
    if (!user) return unauthorized(res);
    try {
      const id = String(req.params.id);
      const row = await ownRow(id, user);
      if (!CONFIRMABLE.has(row.status)) {
        throw new InputError(409, "Submission is already in review", "ALREADY_SUBMITTED");
      }

      const provinceId = Number(req.body?.province_id);
      if (!Number.isInteger(provinceId)) {
        throw new InputError(400, "province_id is required", "INVALID_PROVINCE");
      }
      const province = await database(T.provinces).where({ id: provinceId }).first();
      if (!province) throw new InputError(400, "Unknown province", "INVALID_PROVINCE");

      const dorm = String(req.body?.dorm ?? "").replace(/\s+/g, " ").trim();
      if (dorm.length < 2 || dorm.length > MAX_DORM_LENGTH) {
        throw new InputError(400, "dorm must be 2-120 characters", "INVALID_DORM");
      }
      const notes = String(req.body?.notes ?? "").trim();
      if (notes.length > MAX_NOTES_LENGTH) {
        throw new InputError(400, "notes are too long", "INVALID_NOTES");
      }
      const days = normalizeDays(req.body?.days);
      if (days.length === 0) {
        throw new InputError(400, "Add at least one day with a meal", "INVALID_DAYS");
      }

      const updated = await database(T.submissions)
        .where({ id, user_created: user })
        .whereIn("status", [...CONFIRMABLE])
        .update({
          status: STATUS.pending,
          province_id: provinceId,
          dorm,
          notes: notes || null,
          days: JSON.stringify(days),
          period_start: days[0]!.date,
          period_end: days[days.length - 1]!.date,
          date_updated: deps.now(),
        });
      if (!updated) throw new InputError(409, "Submission is already in review", "ALREADY_SUBMITTED");

      return res.json({ data: { id, status: STATUS.pending } });
    } catch (error) {
      return fail(res, error, "confirm submission");
    }
  });
};
