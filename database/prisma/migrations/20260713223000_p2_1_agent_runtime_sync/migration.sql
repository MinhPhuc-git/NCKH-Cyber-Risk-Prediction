ALTER TABLE "wazuh_agent_bindings"
  ADD COLUMN "last_status_checked_at" TIMESTAMPTZ(3),
  ADD COLUMN "last_status_error" TEXT,
  ADD COLUMN "consecutive_status_failures" INTEGER NOT NULL DEFAULT 0;

CREATE TABLE "device_sync_leases" (
  "device_id" UUID NOT NULL,
  "owner_id" VARCHAR(128) NOT NULL,
  "acquired_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expires_at" TIMESTAMPTZ(3) NOT NULL,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,

  CONSTRAINT "device_sync_leases_pkey" PRIMARY KEY ("device_id")
);

CREATE INDEX "device_sync_leases_expires_at_idx"
  ON "device_sync_leases"("expires_at");

ALTER TABLE "device_sync_leases"
  ADD CONSTRAINT "device_sync_leases_device_id_fkey"
  FOREIGN KEY ("device_id") REFERENCES "devices"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
