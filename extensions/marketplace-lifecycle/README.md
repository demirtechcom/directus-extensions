# Marketplace Lifecycle Extension

Directus hook for PayTR marketplace order reconciliation. It runs every minute by default and:

- queries PayTR before expiring 15-minute payment attempts;
- cancels and fully refunds paid orders that were not accepted within five minutes;
- submits eligible payout instructions when `MARKETPLACE_LIFECYCLE_ACTOR_ID` identifies a Delivr administrator.

Set `MARKETPLACE_LIFECYCLE_CRON` to override the default `* * * * *` schedule. The hook uses the
same PayTR and payment encryption environment variables as the payments endpoint.
