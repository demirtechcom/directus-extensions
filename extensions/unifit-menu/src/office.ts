/**
 * Plain-text views of .xlsx and .docx menus.
 *
 * Claude reads PDFs and images natively but not Office files, and the full parsers (exceljs,
 * mammoth) would roughly triple the size of a bundle that has to fit, with every other extension
 * on the instance, inside one 1 MiB ConfigMap. Both formats are zipped XML, so a small unzip and a
 * tag walk is enough to hand the model the table as text - which is all it needs to structure it.
 */

import { strFromU8, unzipSync } from "fflate";

const MAX_TEXT_CHARS = 200_000;

function decodeXml(text: string): string {
  return text
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&amp;/g, "&");
}

/** Concatenates every `<t>` run inside a fragment (shared strings and inline strings both use it). */
function textRuns(fragment: string): string {
  const runs = [...fragment.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map((m) => m[1] ?? "");
  return decodeXml(runs.join(""));
}

/** Excel stores dates as day serials from 1899-12-30; menus put them in the first column. */
function excelSerialToIso(serial: number): string | null {
  if (!Number.isInteger(serial) || serial < 40_000 || serial > 60_000) return null;
  const date = new Date(Date.UTC(1899, 11, 30) + serial * 86_400_000);
  return date.toISOString().slice(0, 10);
}

function columnIndex(ref: string): number {
  const letters = /^[A-Z]+/.exec(ref)?.[0] ?? "A";
  let index = 0;
  for (const ch of letters) index = index * 26 + (ch.charCodeAt(0) - 64);
  return index - 1;
}

export function xlsxToText(buffer: Uint8Array): string {
  const files = unzipSync(buffer, {
    filter: (file) =>
      file.name === "xl/sharedStrings.xml" || /^xl\/worksheets\/sheet\d+\.xml$/.test(file.name),
  });
  const shared = files["xl/sharedStrings.xml"]
    ? [...strFromU8(files["xl/sharedStrings.xml"]).matchAll(/<si>([\s\S]*?)<\/si>/g)].map((m) =>
        textRuns(m[1] ?? ""),
      )
    : [];

  const sheets = Object.keys(files)
    .filter((name) => name.startsWith("xl/worksheets/"))
    .sort((a, b) => Number(/(\d+)/.exec(a)?.[1]) - Number(/(\d+)/.exec(b)?.[1]));

  const out: string[] = [];
  for (const name of sheets) {
    const xml = strFromU8(files[name]!);
    out.push(`# Sheet ${/(\d+)/.exec(name)?.[1]}`);
    for (const row of xml.matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g)) {
      const cells: string[] = [];
      for (const cell of (row[1] ?? "").matchAll(/<c\s([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
        const attrs = cell[1] ?? "";
        const body = cell[2] ?? "";
        const ref = /r="([A-Z]+\d+)"/.exec(attrs)?.[1] ?? "";
        const type = /t="(\w+)"/.exec(attrs)?.[1];
        const raw = /<v>([\s\S]*?)<\/v>/.exec(body)?.[1];
        let value = "";
        if (type === "s" && raw != null) value = shared[Number(raw)] ?? "";
        else if (type === "inlineStr") value = textRuns(body);
        else if (raw != null) {
          const number = Number(raw);
          const iso = excelSerialToIso(number);
          value = iso ? `${raw} (=${iso})` : decodeXml(raw);
        }
        const index = ref ? columnIndex(ref) : cells.length;
        cells[index] = value.replace(/\s+/g, " ").trim();
      }
      const line = Array.from(cells, (c) => c ?? "").join("\t").trimEnd();
      if (line.trim()) out.push(line);
    }
  }
  return out.join("\n").slice(0, MAX_TEXT_CHARS);
}

export function docxToText(buffer: Uint8Array): string {
  const files = unzipSync(buffer, { filter: (file) => file.name === "word/document.xml" });
  const xml = files["word/document.xml"];
  if (!xml) return "";
  const text = strFromU8(xml)
    .replace(/<\/w:tc>/g, "\t")
    .replace(/<\/w:p>/g, "\n")
    .replace(/<\/w:tr>/g, "\n")
    .replace(/<w:tab\/>/g, "\t")
    .replace(/<w:br\/>/g, "\n")
    .replace(/<[^>]+>/g, "");
  return decodeXml(text)
    .split("\n")
    .map((line) => line.replace(/[  ]+/g, " ").trimEnd())
    .filter((line) => line.trim())
    .join("\n")
    .slice(0, MAX_TEXT_CHARS);
}
