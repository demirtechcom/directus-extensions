import { describe, expect, it } from "bun:test";

import { decryptIban, encryptIban } from "./payment-account-crypto";

const key = Buffer.alloc(32, 7).toString("base64");

describe("restaurant payout account encryption", () => {
  it("round-trips a Turkish IBAN without persisting plaintext", () => {
    const encrypted = encryptIban("TR330006100519786457841326", key);

    expect(encrypted.ciphertext).not.toContain("TR3300");
    expect(encrypted.masked).toBe("TR33 •••• •••• •••• •••• ••13 26");
    expect(decryptIban(encrypted, key)).toBe("TR330006100519786457841326");
  });

  it("rejects invalid keys and non-Turkish IBANs", () => {
    expect(() => encryptIban("TR330006100519786457841326", "short")).toThrow();
    expect(() => encryptIban("GB29NWBK60161331926819", key)).toThrow();
  });
});
