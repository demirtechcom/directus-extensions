/**
 * `bun test src/__tests__` from `directus/extensions/suvia`.
 *
 * The extension has no test runner of its own, and adding one would mean a devDependency on a
 * bundle whose whole deploy is a `wget` of `dist/api.js` — so this uses `node:test`, which is
 * already typed by the `@types/node` the SDK pulls in and which Bun runs as-is. The SDK build
 * follows the declared entry points, so it never reaches this folder. Pure functions only: no
 * express, no knex, no database.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { isMissingRelation, isUniqueViolation } from "../endpoint";

describe("isMissingRelation", () => {
  it("recognises the pg error a missing view produces", () => {
    // The shape knex re-throws when 0003_views.sql was never applied.
    const error = Object.assign(
      new Error('relation "public.suvia_leaderboard_daily" does not exist'),
      { code: "42P01" },
    );
    assert.equal(isMissingRelation(error), true);
  });

  it("does not swallow other database failures", () => {
    // 42703 is undefined_column, 08006 a dropped connection. Both are real 500s: answering them
    // with "apply the migration" sends whoever deployed after the wrong thing.
    assert.equal(isMissingRelation(Object.assign(new Error("nope"), { code: "42703" })), false);
    assert.equal(isMissingRelation(Object.assign(new Error("gone"), { code: "08006" })), false);
    assert.equal(isMissingRelation(new Error("plain")), false);
  });

  it("survives a thrown non-object", () => {
    assert.equal(isMissingRelation(null), false);
    assert.equal(isMissingRelation(undefined), false);
    assert.equal(isMissingRelation("42P01"), false);
  });
});

describe("isUniqueViolation", () => {
  it("recognises the collision the one-log-per-photo index raises", () => {
    // What Postgres raises when two proofs race on the same photo id and the second insert loses
    // to suvia_water_logs_photo_key. The route answers it with the log that won, not a 500.
    const error = Object.assign(
      new Error('duplicate key value violates unique constraint "suvia_water_logs_photo_key"'),
      { code: "23505" },
    );
    assert.equal(isUniqueViolation(error), true);
  });

  it("does not mistake a missing relation or a plain throw for a collision", () => {
    assert.equal(isUniqueViolation(Object.assign(new Error("gone"), { code: "42P01" })), false);
    assert.equal(isUniqueViolation(new Error("plain")), false);
    assert.equal(isUniqueViolation(null), false);
  });
});
