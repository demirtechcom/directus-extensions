import { beforeEach, describe, expect, it, mock } from "bun:test";
import type { Request, Response } from "express";

import createEndpoint, { type EndpointDeps } from "../endpoint";
import type { Extraction } from "../extract";
import createHook from "../review-hook";
import { STATUS, T } from "../shared";
import { FakeDb, fakeServices } from "./fake-db";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const FILE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const FILE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const NOW = new Date("2026-11-08T10:00:00Z");

const EXTRACTION: Extraction = {
  province: "İSTANBUL",
  dorm: "Atatürk Yurdu",
  period_start: "2026-11-01",
  period_end: "2026-11-02",
  days: [
    { date: "2026-11-01", breakfast: ["Peynir"], dinner: ["Mercimek Çorbası", "Pilav"] },
    { date: "2026-11-02", breakfast: ["Yumurta"], dinner: [] },
  ],
  confidence: "high",
  problems: [],
};

type Handler = (req: Request, res: Response) => Promise<unknown>;

function setup(env: Record<string, unknown> = {}) {
  const db = new FakeDb();
  db.table("directus_files").push(
    { id: FILE_A, uploaded_by: USER, type: "application/pdf", filename_download: "menu.pdf" },
    { id: FILE_B, uploaded_by: OTHER, type: "image/jpeg", filename_download: "x.jpg" },
  );
  db.table(T.provinces).push({ id: 34, name: "İstanbul" }, { id: 6, name: "Ankara" });

  const routes: Record<string, Handler> = {};
  const router: any = {
    get: (path: string, h: Handler) => (routes[`GET ${path}`] = h),
    post: (path: string, h: Handler) => (routes[`POST ${path}`] = h),
  };
  const extractMenu = mock(async () => ({ extraction: EXTRACTION, model: "claude-opus-5-5", usage: {} }));
  const deps: EndpointDeps = {
    extractMenu: extractMenu as any,
    buildContent: (async () => ({ blocks: [{ type: "text", text: "x" }], used: [FILE_A], skipped: [] })) as any,
    now: () => NOW,
  };
  const logger = { warn() {}, error() {}, info() {} };
  const context = {
    services: fakeServices(db),
    getSchema: async () => ({}),
    database: db.knex(),
    env: { ANTHROPIC_API_KEY: "test", ...env },
    logger,
  };
  createEndpoint(router, context, deps);

  async function call(method: "GET" | "POST", path: string, opts: { user?: string; body?: any; params?: any } = {}) {
    const res: any = { statusCode: 200 };
    res.status = (c: number) => ((res.statusCode = c), res);
    res.json = (b: unknown) => ((res.body = b), res);
    const req: any = {
      accountability: opts.user === undefined ? { user: USER } : opts.user ? { user: opts.user } : undefined,
      body: opts.body ?? {},
      params: opts.params ?? {},
    };
    await routes[`${method} ${path}`]!(req, res);
    return res;
  }

  /** Lets the fire-and-forget extraction finish. */
  const settle = () => new Promise((r) => setTimeout(r, 0));

  return { db, call, settle, extractMenu, context };
}

describe("POST /submissions", () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it("rejects an unauthenticated call", async () => {
    const res = await t.call("POST", "/submissions", { user: "", body: { file_ids: [FILE_A] } });
    expect(res.statusCode).toBe(401);
  });

  it("refuses a file someone else uploaded", async () => {
    const res = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A, FILE_B] } });
    expect(res.statusCode).toBe(400);
    expect(res.body.errors[0].extensions.code).toBe("INVALID_FILES");
    expect(t.extractMenu).not.toHaveBeenCalled();
  });

  it("creates the row, links the files and stores the extraction", async () => {
    const res = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    expect(res.statusCode).toBe(201);
    expect(res.body.data.status).toBe(STATUS.extracting);
    expect(t.db.table(T.submissionFiles)).toEqual([
      expect.objectContaining({ zest_menu_submissions_id: res.body.data.id, directus_files_id: FILE_A }),
    ]);

    await t.settle();
    const read = await t.call("GET", "/submissions/:id", { params: { id: res.body.data.id } });
    expect(read.body.data).toMatchObject({
      status: STATUS.extracted,
      province_id: 34,
      dorm: "Atatürk Yurdu",
      period_start: "2026-11-01",
      period_end: "2026-11-02",
      confidence: "high",
    });
    expect(read.body.data.days).toHaveLength(2);
  });

  it("stops extracting at the daily limit, without spending a call", async () => {
    const limited = setup({ UNIFIT_MENU_DAILY_LIMIT: "2" });
    for (let i = 0; i < 2; i++) {
      await limited.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    }
    await limited.settle();
    const third = await limited.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    expect(third.body.data.status).toBe(STATUS.limitReached);
    expect(limited.extractMenu).toHaveBeenCalledTimes(2);
  });

  it("does not count failed extractions against the limit", async () => {
    const limited = setup({ UNIFIT_MENU_DAILY_LIMIT: "1" });
    limited.extractMenu.mockImplementationOnce(async () => {
      throw new Error("boom");
    });
    await limited.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    await limited.settle();
    expect(limited.db.table(T.submissions)[0]!.status).toBe(STATUS.extractFailed);

    const retry = await limited.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    expect(retry.body.data.status).toBe(STATUS.extracting);
  });

  it("stops counting an extraction abandoned more than ten minutes ago", async () => {
    const limited = setup({ UNIFIT_MENU_DAILY_LIMIT: "1" });
    limited.db.table(T.submissions).push({
      id: "33333333-3333-4333-8333-333333333333",
      user_created: USER,
      date_created: new Date(NOW.getTime() - 11 * 60 * 1000),
      status: STATUS.extracting,
    });
    const res = await limited.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    expect(res.body.data.status).toBe(STATUS.extracting);
  });

  it("marks a result with no days as failed", async () => {
    t.extractMenu.mockImplementationOnce(async () => ({
      extraction: { ...EXTRACTION, days: [] },
      model: "m",
      usage: {},
    }));
    await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    await t.settle();
    expect(t.db.table(T.submissions)[0]!.status).toBe(STATUS.extractFailed);
  });
});

describe("GET /submissions/:id", () => {
  it("does not show another user's submission", async () => {
    const t = setup();
    const created = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    const res = await t.call("GET", "/submissions/:id", { user: OTHER, params: { id: created.body.data.id } });
    expect(res.statusCode).toBe(404);
  });
});

describe("POST /submissions/:id/confirm", () => {
  const body = {
    province_id: 34,
    dorm: "Atatürk Yurdu",
    days: [{ date: "2026-11-05", breakfast: ["Simit"], dinner: ["Kuru Fasulye"] }],
  };

  it("moves the row to pending with the user's table", async () => {
    const t = setup();
    const created = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    await t.settle();
    const res = await t.call("POST", "/submissions/:id/confirm", { params: { id: created.body.data.id }, body });
    expect(res.statusCode).toBe(200);
    const row = t.db.table(T.submissions)[0]!;
    expect(row.status).toBe(STATUS.pending);
    expect(JSON.parse(row.days)).toEqual(body.days);
    expect(row.period_start).toBe("2026-11-05");
  });

  it("keeps a hand-confirmed table when the extraction finishes late", async () => {
    const t = setup();
    let release!: () => void;
    t.extractMenu.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ extraction: EXTRACTION, model: "m", usage: {} });
        }) as any,
    );
    const created = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    await t.settle();
    await t.call("POST", "/submissions/:id/confirm", { params: { id: created.body.data.id }, body });
    release();
    await t.settle();
    const row = t.db.table(T.submissions)[0]!;
    expect(row.status).toBe(STATUS.pending);
    expect(JSON.parse(row.days)).toEqual(body.days);
  });

  it("rejects an unknown province, a short dorm and an empty table", async () => {
    const t = setup();
    const created = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    const id = created.body.data.id;
    const codes = [];
    for (const patch of [{ province_id: 99 }, { dorm: "A" }, { days: [{ date: "2026-11-05", breakfast: [], dinner: [] }] }]) {
      const res = await t.call("POST", "/submissions/:id/confirm", { params: { id }, body: { ...body, ...patch } });
      codes.push(res.body.errors[0].extensions.code);
    }
    expect(codes).toEqual(["INVALID_PROVINCE", "INVALID_DORM", "INVALID_DAYS"]);
  });

  it("cannot confirm twice", async () => {
    const t = setup();
    const created = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    const id = created.body.data.id;
    await t.call("POST", "/submissions/:id/confirm", { params: { id }, body });
    const again = await t.call("POST", "/submissions/:id/confirm", { params: { id }, body });
    expect(again.statusCode).toBe(409);
  });
});

describe("review hook", () => {
  async function approvedSubmission(mode?: "replace") {
    const t = setup();
    const created = await t.call("POST", "/submissions", { body: { file_ids: [FILE_A] } });
    await t.settle();
    await t.call("POST", "/submissions/:id/confirm", {
      params: { id: created.body.data.id },
      body: {
        province_id: 34,
        dorm: "Atatürk Yurdu",
        days: [{ date: "2026-11-05", breakfast: ["Simit"], dinner: ["Kuru Fasulye"] }],
      },
    });
    const id = created.body.data.id;
    t.db.table(T.provinceMenus).push({
      id: 1,
      province_id: 34,
      date: "2026-11-05",
      type: "DINNER",
      items: ["Old dinner"],
      calorie_range: [700, 900],
    });
    const row = t.db.table(T.submissions)[0]!;
    row.status = STATUS.approved;
    if (mode) row.publish_mode = mode;

    let handler!: (meta: any) => Promise<void>;
    createHook({ action: (_event: string, h: any) => (handler = h) }, t.context);
    return { t, id, row, fire: (status: string) => handler({ keys: [id], payload: { status } }) };
  }

  it("publishes new meals and skips existing ones by default", async () => {
    const { t, row, fire } = await approvedSubmission();
    await fire(STATUS.approved);
    expect(row.status).toBe(STATUS.published);
    const menus = t.db.table(T.provinceMenus);
    expect(menus).toHaveLength(2);
    expect(menus.find((m) => m.type === "BREAKFAST")).toMatchObject({
      province_id: 34,
      date: "2026-11-05",
      items: ["Simit"],
      calorie_range: [500, 700],
    });
    expect(menus.find((m) => m.type === "DINNER")!.items).toEqual(["Old dinner"]);
    expect(JSON.parse(row.publish_log).skipped).toEqual([{ date: "2026-11-05", type: "DINNER" }]);
  });

  it("replaces existing meals when asked, and a rollback restores them", async () => {
    const { t, row, fire } = await approvedSubmission("replace");
    await fire(STATUS.approved);
    expect(t.db.table(T.provinceMenus).find((m) => m.type === "DINNER")!.items).toEqual(["Kuru Fasulye"]);

    row.status = STATUS.rolledBack;
    await fire(STATUS.rolledBack);
    const menus = t.db.table(T.provinceMenus);
    expect(menus).toHaveLength(1);
    expect(menus[0]).toMatchObject({ id: 1, items: ["Old dinner"] });
    expect(row.status).toBe(STATUS.rolledBack);
    expect(JSON.parse(row.publish_log).rolled_back_at).toBeTruthy();
  });

  it("marks a submission without a province as publish_failed", async () => {
    const { row, fire } = await approvedSubmission();
    row.province_id = null;
    await fire(STATUS.approved);
    expect(row.status).toBe(STATUS.publishFailed);
    expect(JSON.parse(row.publish_log).error).toContain("province");
  });
});
