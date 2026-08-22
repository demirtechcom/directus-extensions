/**
 * The two Claude vision calls, ported verbatim from the v1 Supabase Edge Functions
 * (ported from the v1 verify-water-photo edge function).
 *
 * The prompts are reproduced word for word and are NOT a place to be clever. They were tuned
 * against real user photos over several releases, and the tone rules in them are a product
 * decision: a rejection has to read as an invitation to try again, never as an accusation. The
 * bar is deliberately generous — "if unsure, APPROVE" — because the cost of wrongly rejecting a
 * real glass of water is a user who stops trusting the app, and the cost of wrongly approving a
 * photo is one unearned log entry.
 *
 * The model is pinned to a dated snapshot rather than the `claude-haiku-4-5` alias. A classifier
 * whose verdicts change under people because the alias moved is worse than one that needs an
 * explicit bump: the prompts above were calibrated against this exact snapshot.
 */

import Anthropic from "@anthropic-ai/sdk";

const HAIKU = "claude-haiku-4-5-20251001";

/** Verdict text must fit comfortably; 100 truncated mid-JSON in v1 and JSON.parse then threw. */
const WATER_MAX_TOKENS = 300;

export type Locale = "tr" | "en";

const SUPPORTED_LOCALES: Locale[] = ["tr", "en"];

export function normalizeLocale(value: unknown): Locale {
  return SUPPORTED_LOCALES.includes(value as Locale) ? (value as Locale) : "tr";
}

// ── water ───────────────────────────────────────────────────────────────────────────────────

const WATER_PROMPTS: Record<Locale, string> = {
  tr: `Su içme uygulaması için fotoğraf doğrulayıcısısın.

"reason": Türkçe, EN FAZLA 8 KELİME, nazik/teşvik edici — asla suçlayıcı/azarlayıcı değil.

ONAYLA: içilebilir su içerdiği makul olan herhangi bir kap görünüyorsa (bardak, şişe,
matara, termos vb.) — kapalı/opak olabilir, suyun görünmesi şart değil.

REDDET sadece: içme kabı hiç yoksa (yemek/bitki/alakasız nesne), ekran/basılı fotoğraf
gibiyse (moiré, çerçeve, parlama), veya görüntü tamamen bulanık/karanlıksa.

Kararsızsan ONAYLA.`,
  en: `You are a photo verifier for a water-drinking app.

"reason": in English, AT MOST 8 WORDS, kind/encouraging — never accusatory or scolding.

APPROVE: if any plausible drinking vessel is visible (glass, bottle, flask, thermos, etc.)
— it may be closed/opaque, the water itself doesn't need to be visible.

REJECT only if: no drinking vessel is present (food/plant/unrelated object), it looks like
a screen/printed photo (moiré, frame, glare), or the image is completely blurry/dark.

If unsure, APPROVE.`,
};

const WATER_SCHEMA = {
  type: "object",
  properties: {
    is_water: { type: "boolean" },
    confidence: { type: "number" },
    reason: { type: "string" },
  },
  required: ["is_water", "confidence", "reason"],
  additionalProperties: false,
};

export interface WaterVerdict {
  is_water: boolean;
  confidence: number;
  reason: string;
  model: string;
}

// ── client ──────────────────────────────────────────────────────────────────────────────────

let client: Anthropic | null = null;

function anthropic(apiKey: string): Anthropic {
  if (!client) client = new Anthropic({ apiKey });
  return client;
}

/** Pulls the single text block out of a structured-output response and parses it. */
function readJsonBlock(message: Anthropic.Message): Record<string, unknown> {
  if (message.stop_reason === "max_tokens") {
    throw new Error("Model response truncated (max_tokens too low)");
  }
  const block = message.content.find((b) => b.type === "text");
  const text = block?.type === "text" ? block.text : "";
  if (!text) throw new Error("Empty model response");
  return JSON.parse(text);
}

export async function classifyWater(
  apiKey: string,
  photoBase64: string,
  locale: Locale,
): Promise<WaterVerdict> {
  const message = await anthropic(apiKey).messages.create({
    model: HAIKU,
    max_tokens: WATER_MAX_TOKENS,
    // A yes/no classification gains nothing from reasoning, and the latency shows up in front
    // of a user standing there holding a glass.
    thinking: { type: "disabled" },
    output_config: { format: { type: "json_schema", schema: WATER_SCHEMA } },
    messages: [
      {
        role: "user",
        content: [
          {
            type: "image",
            source: { type: "base64", media_type: "image/jpeg", data: photoBase64 },
          },
          { type: "text", text: WATER_PROMPTS[locale] },
        ],
      },
    ],
  });

  const parsed = readJsonBlock(message);
  return {
    is_water: !!parsed.is_water,
    confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0,
    reason: typeof parsed.reason === "string" ? parsed.reason : "",
    model: HAIKU,
  };
}
