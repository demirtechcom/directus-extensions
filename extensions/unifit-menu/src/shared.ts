/**
 * Shapes and rules shared by the endpoint (what a user may submit) and the review hook (what an
 * editor may publish). Both sides validate with the same functions on purpose: a day the endpoint
 * accepted but the hook rejected would leave a submission an editor can approve and never publish.
 */

/**
 * The UNI FIT collection names. They live in the app's `clients/app/src/types/tables.ts` as well,
 * and they are frozen there: renaming one is a live-database migration, not a code change.
 */
export const T = {
  submissions: "zest_menu_submissions",
  submissionFiles: "zest_menu_submissions_files",
  provinceMenus: "zest_province_menus",
  provinces: "provinces",
} as const;

export const STATUS = {
  /** Row created, extraction running in the background. */
  extracting: "extracting",
  /** The model returned a usable table; the user has not confirmed it yet. */
  extracted: "extracted",
  /** Extraction ran and failed. Does not count against the daily limit. */
  extractFailed: "extract_failed",
  /** Over the daily limit: no extraction, the user fills the table in by hand. */
  limitReached: "limit_reached",
  /** The user confirmed the table. This is the editor's queue. */
  pending: "pending",
  /** Set by an editor; the review hook publishes and moves it on. */
  approved: "approved",
  published: "published",
  publishFailed: "publish_failed",
  rejected: "rejected",
  /** Set by an editor on a published row; the review hook undoes the publish. */
  rolledBack: "rolled_back",
} as const;

export type Status = (typeof STATUS)[keyof typeof STATUS];

/** Statuses a user may still confirm from. Anything later belongs to the editor. */
export const CONFIRMABLE: ReadonlySet<string> = new Set([
  STATUS.extracting,
  STATUS.extracted,
  STATUS.extractFailed,
  STATUS.limitReached,
]);

/** Extractions that ran and produced something: these are the ones the daily limit counts. */
export const COUNTED_STATUSES: readonly string[] = [
  STATUS.extracted,
  STATUS.pending,
  STATUS.approved,
  STATUS.published,
  STATUS.publishFailed,
  STATUS.rejected,
  STATUS.rolledBack,
];

export const MAX_FILES = 5;
export const MAX_DAYS = 62;
export const MAX_ITEMS_PER_MEAL = 20;
export const MAX_ITEM_LENGTH = 120;
export const MAX_DORM_LENGTH = 120;
export const MAX_NOTES_LENGTH = 1600;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

export interface MenuDay {
  date: string;
  breakfast: string[];
  dinner: string[];
}

export class InputError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

export function isIsoDate(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = ISO_DATE_RE.exec(value);
  if (!match) return false;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
  );
}

function cleanItems(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const items: string[] = [];
  for (const entry of raw) {
    const name = String(typeof entry === "string" ? entry : ((entry as any)?.name ?? ""))
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, MAX_ITEM_LENGTH);
    const key = name.toLocaleLowerCase("tr");
    if (!name || seen.has(key)) continue;
    seen.add(key);
    items.push(name);
    if (items.length >= MAX_ITEMS_PER_MEAL) break;
  }
  return items;
}

/**
 * Turns whatever a model or a phone sent into a clean, sorted day list.
 *
 * Lenient about content and strict about shape: an invalid date or a day with no food at all is
 * dropped rather than failing the whole menu, because one unreadable row in a photographed month
 * should not throw away the other thirty. Two rows for the same date are merged, which is what a
 * menu printed as separate breakfast and dinner tables extracts to.
 */
export function normalizeDays(raw: unknown): MenuDay[] {
  if (!Array.isArray(raw)) return [];
  const byDate = new Map<string, MenuDay>();
  for (const entry of raw) {
    const date = (entry as any)?.date;
    if (!isIsoDate(date)) continue;
    const breakfast = cleanItems((entry as any)?.breakfast);
    const dinner = cleanItems((entry as any)?.dinner);
    const existing = byDate.get(date);
    if (existing) {
      existing.breakfast = cleanItems([...existing.breakfast, ...breakfast]);
      existing.dinner = cleanItems([...existing.dinner, ...dinner]);
    } else {
      byDate.set(date, { date, breakfast, dinner });
    }
  }
  return [...byDate.values()]
    .filter((day) => day.breakfast.length > 0 || day.dinner.length > 0)
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(0, MAX_DAYS);
}

/**
 * Midnight in Europe/Istanbul, as a UTC instant. Turkey has been on fixed UTC+3 with no DST since
 * 2016, so a constant offset is exact - and it is the day boundary a student in a dorm means by
 * "today", whatever timezone the server happens to run in.
 */
export function istanbulDayStart(now: Date): Date {
  const offsetMs = 3 * 60 * 60 * 1000;
  const local = new Date(now.getTime() + offsetMs);
  local.setUTCHours(0, 0, 0, 0);
  return new Date(local.getTime() - offsetMs);
}

/** Lowercases with Turkish rules and folds the letters people type both ways (İstanbul/Istanbul). */
export function foldTurkish(value: string): string {
  return value
    .toLocaleLowerCase("tr")
    .replace(/ı/g, "i")
    .replace(/ğ/g, "g")
    .replace(/ü/g, "u")
    .replace(/ş/g, "s")
    .replace(/ö/g, "o")
    .replace(/ç/g, "c")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

export interface Province {
  id: number;
  name: string;
}

/**
 * Finds the province a free-text name refers to, or null.
 *
 * Exact match first, then a name that appears as a whole word inside the text - a KYK header
 * reads "İSTANBUL BÖLGE MÜDÜRLÜĞÜ ... YURDU", not "İstanbul". Longer names win so that a header
 * naming "Kahramanmaraş" is not claimed by a shorter name it happens to contain.
 */
export function matchProvince(text: string | null | undefined, provinces: Province[]): number | null {
  if (!text) return null;
  const folded = foldTurkish(text);
  if (!folded) return null;
  const candidates = provinces
    .map((p) => ({ id: p.id, name: foldTurkish(p.name) }))
    .filter((p) => p.name.length > 0);
  const exact = candidates.find((p) => p.name === folded);
  if (exact) return exact.id;
  const padded = ` ${folded} `;
  const contained = candidates
    .filter((p) => padded.includes(` ${p.name} `))
    .sort((a, b) => b.name.length - a.name.length);
  return contained[0]?.id ?? null;
}

/** Reads and range-checks the configured default calorie range for a meal type. */
export function calorieRange(env: Record<string, unknown>, type: "BREAKFAST" | "DINNER"): [number, number] {
  const fallback: [number, number] = type === "BREAKFAST" ? [500, 700] : [700, 900];
  const raw = String(env[`UNIFIT_MENU_CALORIES_${type}`] ?? "");
  const parts = raw.split(",").map((part) => Number(part.trim()));
  if (parts.length === 2 && parts.every((n) => Number.isFinite(n) && n > 0) && parts[0]! <= parts[1]!) {
    return [parts[0]!, parts[1]!];
  }
  return fallback;
}

/** pg returns json columns parsed and sqlite returns strings; accept both. */
export function parseJson<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

/** A `date` column as `YYYY-MM-DD`, whether the driver hands back a string or a local-midnight Date. */
export function dateColumn(value: unknown): string | null {
  if (value instanceof Date) {
    const m = String(value.getMonth() + 1).padStart(2, "0");
    const d = String(value.getDate()).padStart(2, "0");
    return `${value.getFullYear()}-${m}-${d}`;
  }
  if (typeof value === "string" && isIsoDate(value.slice(0, 10))) return value.slice(0, 10);
  return null;
}
