/**
 * Photo I/O against `directus_files`, replacing v1's two private Supabase Storage buckets.
 *
 * Proof photos are uploaded here by the server, never by the client: the file id is what
 * `suvia_resolve_challenge` writes onto the challenge, so a client that could upload its own
 * file and hand back the id would be supplying its own evidence.
 */

import { Readable } from "node:stream";

/** ~200KB. A 512px JPEG lands around 40KB, so this is a ceiling, not a target. */
export const MAX_PHOTO_BYTES = 200_000;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class PhotoError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Decodes and size-checks a client-supplied base64 photo.
 *
 * Checked twice on purpose: the string length rejects an oversized payload before allocating a
 * buffer for it, and the byte length is the real limit once decoded.
 */
export function decodePhoto(value: unknown): Buffer {
  if (!value || typeof value !== "string") {
    throw new PhotoError(400, "Missing photo_base64");
  }
  if (value.length > MAX_PHOTO_BYTES * 1.4) {
    throw new PhotoError(413, "Photo too large");
  }
  let buffer: Buffer;
  try {
    buffer = Buffer.from(value, "base64");
  } catch {
    throw new PhotoError(400, "Invalid photo encoding");
  }
  // Buffer.from is lenient with malformed base64 — an empty result is the only reliable signal.
  if (buffer.byteLength === 0) throw new PhotoError(400, "Invalid photo encoding");
  if (buffer.byteLength > MAX_PHOTO_BYTES) throw new PhotoError(413, "Photo too large");
  return buffer;
}

interface UploadArgs {
  services: any;
  schema: any;
  knex: any;
  accountability: any;
  env: Record<string, any>;
  buffer: Buffer;
  filename: string;
}

/**
 * Writes a photo to directus_files and returns its id.
 *
 * The caller's accountability with `admin` raised — both halves matter, and neither works alone.
 *
 * Without `admin`, the upload is rejected. Proof photos go to SUVIA_PHOTO_FOLDER, and the
 * client's own `directus_files:create` permission is scoped to the avatar folder precisely so it
 * can never write into the folder the purge sweeps. A non-admin FilesService runs its create
 * through that same validation, so passing the caller's accountability straight through means
 * every photo verification 500s — the server refusing itself with the rule written to constrain
 * the client.
 *
 * Without the caller's `user`, the file lands with `uploaded_by = null`, and `POST /water-logs`
 * finds the photo by `{ id, uploaded_by: user }`. That lookup is what stops someone attaching
 * another account's verified photo to their own water log, so it cannot be dropped — the file
 * has to stay attributed to the person who took it.
 */
export async function uploadPhoto({
  services,
  schema,
  knex,
  accountability,
  env,
  buffer,
  filename,
}: UploadArgs): Promise<string> {
  const { FilesService } = services;
  const files = new FilesService({
    schema,
    knex,
    accountability: { ...accountability, admin: true },
  });

  // STORAGE_LOCATIONS is a comma-separated list; the first entry is the default location and is
  // what the Directus admin writes to, so proof photos land beside everything else.
  const storage = String(env.STORAGE_LOCATIONS ?? "local")
    .split(",")[0]!
    .trim();

  return files.uploadOne(Readable.from(buffer), {
    storage,
    filename_download: filename,
    type: "image/jpeg",
    title: filename,
    folder: env.SUVIA_PHOTO_FOLDER || null,
    // Stated rather than left to FilesService to derive from accountability. Same value either
    // way, but a null here is invisible until a user taps "+" and their own photo answers 404.
    uploaded_by: accountability?.user ?? null,
  });
}
