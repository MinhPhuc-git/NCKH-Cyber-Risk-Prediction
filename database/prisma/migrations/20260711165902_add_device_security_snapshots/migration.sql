-- CreateTable
CREATE TABLE "device_security_snapshots" (
    "id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "wazuh_agent_id" VARCHAR(16) NOT NULL,
    "agent_name" VARCHAR(255),
    "agent_status" VARCHAR(40),
    "agent_ip" VARCHAR(255),
    "last_keep_alive_at" TIMESTAMPTZ(3),
    "window_minutes" INTEGER NOT NULL DEFAULT 1440,
    "alert_count" INTEGER NOT NULL DEFAULT 0,
    "max_rule_level" INTEGER,
    "low_count" INTEGER NOT NULL DEFAULT 0,
    "medium_count" INTEGER NOT NULL DEFAULT 0,
    "high_count" INTEGER NOT NULL DEFAULT 0,
    "critical_count" INTEGER NOT NULL DEFAULT 0,
    "risk_score" INTEGER NOT NULL DEFAULT 0,
    "risk_label" VARCHAR(40) NOT NULL DEFAULT 'Không xác định',
    "top_rules" JSONB NOT NULL,
    "latest_alerts" JSONB NOT NULL,
    "hardware" JSONB,
    "inventory" JSONB,
    "calculated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_successful_at" TIMESTAMPTZ(3),
    "sync_error" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "device_security_snapshots_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "device_security_snapshots_device_id_key" ON "device_security_snapshots"("device_id");

-- CreateIndex
CREATE INDEX "device_security_snapshots_wazuh_agent_id_idx" ON "device_security_snapshots"("wazuh_agent_id");

-- CreateIndex
CREATE INDEX "device_security_snapshots_agent_status_calculated_at_idx" ON "device_security_snapshots"("agent_status", "calculated_at");

-- CreateIndex
CREATE INDEX "device_security_snapshots_risk_score_calculated_at_idx" ON "device_security_snapshots"("risk_score", "calculated_at");

-- AddForeignKey
ALTER TABLE "device_security_snapshots" ADD CONSTRAINT "device_security_snapshots_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
