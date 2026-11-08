import { describe, expect, it } from "bun:test";
import { strToU8, zipSync } from "fflate";

import { buildContent, parseExtraction } from "../extract";
import { docxToText, xlsxToText } from "../office";
import {
  calorieRange,
  dateColumn,
  isIsoDate,
  istanbulDayStart,
  matchProvince,
  normalizeDays,
} from "../shared";

const PROVINCES = [
  { id: 34, name: "İstanbul" },
  { id: 6, name: "Ankara" },
  { id: 46, name: "Kahramanmaraş" },
  { id: 33, name: "Mersin" },
];

describe("normalizeDays", () => {
  it("drops invalid dates and empty days, merges duplicates, trims and sorts", () => {
    const days = normalizeDays([
      { date: "2026-11-02", breakfast: [" Peynir ", "Zeytin"], dinner: [] },
      { date: "2026-02-30", breakfast: ["Simit"], dinner: [] },
      { date: "2026-11-01", breakfast: [], dinner: [] },
      { date: "2026-11-02", breakfast: ["peynir"], dinner: ["Mercimek Çorbası"] },
      { date: "2026-11-03", breakfast: [{ name: "Yumurta" }], dinner: [""] },
    ]);
    expect(days).toEqual([
      { date: "2026-11-02", breakfast: ["Peynir", "Zeytin"], dinner: ["Mercimek Çorbası"] },
      { date: "2026-11-03", breakfast: ["Yumurta"], dinner: [] },
    ]);
  });

  it("returns nothing for non-arrays", () => {
    expect(normalizeDays(null)).toEqual([]);
    expect(normalizeDays({})).toEqual([]);
  });
});

describe("matchProvince", () => {
  it("matches exact names regardless of Turkish casing", () => {
    expect(matchProvince("ISTANBUL", PROVINCES)).toBe(34);
    expect(matchProvince("istanbul", PROVINCES)).toBe(34);
  });

  it("finds a province named inside a KYK header", () => {
    expect(matchProvince("KYK ANKARA BÖLGE MÜDÜRLÜĞÜ", PROVINCES)).toBe(6);
    expect(matchProvince("Kahramanmaraş Merkez Yurdu", PROVINCES)).toBe(46);
  });

  it("returns null when nothing matches", () => {
    expect(matchProvince("Atatürk Yurdu", PROVINCES)).toBeNull();
    expect(matchProvince(null, PROVINCES)).toBeNull();
  });
});

describe("istanbulDayStart", () => {
  it("is 21:00 UTC of the previous day", () => {
    expect(istanbulDayStart(new Date("2026-11-08T10:00:00Z")).toISOString()).toBe(
      "2026-11-07T21:00:00.000Z",
    );
    // 22:30 UTC is already the next day in Istanbul.
    expect(istanbulDayStart(new Date("2026-11-08T22:30:00Z")).toISOString()).toBe(
      "2026-11-08T21:00:00.000Z",
    );
  });
});

describe("calorieRange", () => {
  it("reads a configured range and falls back on a bad one", () => {
    expect(calorieRange({ UNIFIT_MENU_CALORIES_DINNER: "650, 950" }, "DINNER")).toEqual([650, 950]);
    expect(calorieRange({ UNIFIT_MENU_CALORIES_DINNER: "950,650" }, "DINNER")).toEqual([700, 900]);
    expect(calorieRange({}, "BREAKFAST")).toEqual([500, 700]);
  });
});

describe("dates", () => {
  it("validates and reads date columns", () => {
    expect(isIsoDate("2026-11-30")).toBe(true);
    expect(isIsoDate("2026-11-31")).toBe(false);
    expect(dateColumn("2026-11-30T00:00:00")).toBe("2026-11-30");
    expect(dateColumn(new Date(2026, 10, 30))).toBe("2026-11-30");
    expect(dateColumn(null)).toBeNull();
  });
});

describe("parseExtraction", () => {
  it("keeps valid fields and cleans the days", () => {
    const result = parseExtraction(
      JSON.stringify({
        province: "İstanbul",
        dorm: " Atatürk Yurdu ",
        period_start: "2026-11-01",
        period_end: "nope",
        days: [{ date: "2026-11-01", breakfast: ["Peynir"], dinner: ["Pilav"] }],
        confidence: "weird",
        problems: ["day 5 unreadable"],
      }),
    );
    expect(result.dorm).toBe("Atatürk Yurdu");
    expect(result.period_end).toBeNull();
    expect(result.confidence).toBe("low");
    expect(result.days).toHaveLength(1);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseExtraction("not json")).toThrow();
  });
});

describe("office files", () => {
  it("turns an xlsx sheet into tab-separated text with dates resolved", () => {
    const xlsx = zipSync({
      "xl/sharedStrings.xml": strToU8(
        "<sst><si><t>Tarih</t></si><si><t>Kahvaltı</t></si><si><t>Peynir &amp; Zeytin</t></si></sst>",
      ),
      "xl/worksheets/sheet1.xml": strToU8(
        '<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>' +
          '<row r="2"><c r="A2"><v>46327</v></c><c r="B2" t="s"><v>2</v></c></row></sheetData></worksheet>',
      ),
    });
    expect(xlsxToText(xlsx)).toBe("# Sheet 1\nTarih\tKahvaltı\n46327 (=2026-11-01)\tPeynir & Zeytin");
  });

  it("turns a docx table into lines and tabs", () => {
    const docx = zipSync({
      "word/document.xml": strToU8(
        "<w:document><w:body><w:tbl><w:tr><w:tc><w:p><w:r><w:t>1 Kasım</w:t></w:r></w:p></w:tc>" +
          "<w:tc><w:p><w:r><w:t>Mercimek Çorbası</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>",
      ),
    });
    expect(docxToText(docx)).toContain("1 Kasım");
    expect(docxToText(docx)).toContain("Mercimek Çorbası");
  });
});

describe("buildContent", () => {
  it("routes each file by type and reports what it skipped", async () => {
    const reads: [string, boolean][] = [];
    const built = await buildContent(
      [
        { id: "a", type: "application/pdf", filename_download: "menu.pdf" },
        { id: "b", type: "image/heic", filename_download: "IMG_1.HEIC" },
        { id: "c", type: "application/zip", filename_download: "x.zip" },
        { id: "d", type: "image/jpeg", filename_download: "broken.jpg" },
      ],
      async (id, asJpeg) => {
        reads.push([id, asJpeg]);
        if (id === "d") throw new Error("cannot decode");
        return Buffer.from("data");
      },
    );
    expect(reads).toEqual([
      ["a", false],
      ["b", true],
      ["d", true],
    ]);
    expect(built.blocks.map((b) => b.type)).toEqual(["document", "image"]);
    expect(built.used).toEqual(["a", "b"]);
    expect(built.skipped.map((s) => s.id)).toEqual(["c", "d"]);
  });
});
