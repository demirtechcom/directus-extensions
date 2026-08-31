import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface EncryptedIban {
  ciphertext: string;
  iv: string;
  authTag: string;
  masked: string;
}

export function encryptIban(rawIban: string, base64Key: string): EncryptedIban {
  const iban = normalizeTurkishIban(rawIban);
  const key = encryptionKey(base64Key);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(iban, "utf8"), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    masked: `${iban.slice(0, 4)} •••• •••• •••• •••• ••${iban.slice(-4, -2)} ${iban.slice(-2)}`,
  };
}

export function decryptIban(encrypted: EncryptedIban, base64Key: string): string {
  const key = encryptionKey(base64Key);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(encrypted.iv, "base64"));
  decipher.setAuthTag(Buffer.from(encrypted.authTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  return normalizeTurkishIban(plaintext);
}

function encryptionKey(value: string): Buffer {
  const key = Buffer.from(value, "base64");
  if (key.length !== 32) {
    throw new Error("PAYMENT_ACCOUNT_ENCRYPTION_KEY must be a base64-encoded 32-byte key");
  }
  return key;
}

function normalizeTurkishIban(value: string): string {
  const iban = value.replaceAll(" ", "").toUpperCase();
  if (!/^TR\d{24}$/.test(iban)) {
    throw new Error("A valid Turkish IBAN is required");
  }
  return iban;
}
