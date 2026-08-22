/**
 * Deletes proof photos 24 hours after they were taken.
 *
 * The photos exist for exactly one vision call. Nothing in the app ever displays them again, so
 * keeping them is storage cost and KVKK surface with no upside. v1 did this with pg_cron and
 * pg_net calling the storage API back, which needed the service-role key sitting in the database
 * vault; a scheduled hook needs no credential at all.
 *
 * One safety property matters more than the deletion itself: it refuses to run without
 * SUVIA_PHOTO_FOLDER. cms.demirtech.com is shared with another product; without a folder to
 * scope to, "every file older than 24 hours" would mean that product's files too. A missing
 * folder is a configuration error, and the correct response to it is to delete nothing.
 */

import { defineHook } from "@directus/extensions-sdk";

const RETENTION_HOURS = 24;
/** Bounded so a backlog is worked off over several runs rather than in one long transaction. */
const BATCH = 500;

export default defineHook(({ schedule }, { services, database, getSchema, env, logger }) => {
  const folder = env.SUVIA_PHOTO_FOLDER;

  if (!folder) {
    logger.warn(
      "[suvia-purge] SUVIA_PHOTO_FOLDER is not set — proof photos will NOT be purged. " +
        "Set it to the Directus folder id holding Suvia's photos.",
    );
    return;
  }

  schedule("0 * * * *", async () => {
    try {
      const cutoff = new Date(Date.now() - RETENTION_HOURS * 60 * 60 * 1000).toISOString();

      const stale = await database("directus_files")
        .where("folder", folder)
        .andWhere("uploaded_on", "<", cutoff)
        .limit(BATCH)
        .pluck("id");

      if (stale.length === 0) return;

      const { FilesService } = services;
      const files = new FilesService({
        schema: await getSchema(),
        knex: database,
        // A scheduled job has no request and therefore no accountability; it is the system
        // acting on its own retention policy, not a user acting on their own files.
        accountability: { admin: true, role: null, user: null },
      });

      await files.deleteMany(stale);
      logger.info(
        `[suvia-purge] deleted ${stale.length} proof photos older than ${RETENTION_HOURS}h`,
      );
    } catch (error) {
      // Never throw out of a scheduled hook — an unhandled rejection here takes the scheduler
      // down with it, and a failed purge is not worth losing every other job on the instance.
      logger.error(`[suvia-purge] ${(error as Error)?.message ?? error}`);
    }
  });
});
