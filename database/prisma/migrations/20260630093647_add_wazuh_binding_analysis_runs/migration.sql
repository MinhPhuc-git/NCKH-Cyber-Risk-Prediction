-- CreateEnum
CREATE TYPE "AnalysisRunStatus" AS ENUM ('QUEUED', 'COLLECTING_EVENTS', 'ANALYZING', 'COMPLETED', 'FAILED');

-- CreateTable
CREATE TABLE "wazuh_agent_bindings" (
    "id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "wazuh_agent_id" VARCHAR(16) NOT NULL,
    "wazuh_agent_name" VARCHAR(255) NOT NULL,
    "last_known_status" VARCHAR(40),
    "last_keep_alive_at" TIMESTAMPTZ(3),
    "last_synchronized_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "wazuh_agent_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "analysis_runs" (
    "id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "status" "AnalysisRunStatus" NOT NULL DEFAULT 'QUEUED',
    "window_start" TIMESTAMPTZ(3) NOT NULL,
    "window_end" TIMESTAMPTZ(3) NOT NULL,
    "requested_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMPTZ(3),
    "event_count" INTEGER NOT NULL DEFAULT 0,
    "max_rule_level" INTEGER,
    "summary" JSONB,
    "error_message" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "analysis_runs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "wazuh_agent_bindings_device_id_key" ON "wazuh_agent_bindings"("device_id");

-- CreateIndex
CREATE UNIQUE INDEX "wazuh_agent_bindings_wazuh_agent_id_key" ON "wazuh_agent_bindings"("wazuh_agent_id");

-- CreateIndex
CREATE INDEX "analysis_runs_device_id_requested_at_idx" ON "analysis_runs"("device_id", "requested_at");

-- CreateIndex
CREATE INDEX "analysis_runs_device_id_status_idx" ON "analysis_runs"("device_id", "status");

-- AddForeignKey
ALTER TABLE "wazuh_agent_bindings" ADD CONSTRAINT "wazuh_agent_bindings_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "analysis_runs" ADD CONSTRAINT "analysis_runs_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
