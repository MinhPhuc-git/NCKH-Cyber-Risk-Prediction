-- CYRP Phase 2: CTI catalog, Wazuh vulnerability state, endpoint context history, and synchronization provenance.

CREATE TYPE "SyncSourceType" AS ENUM (
  'CTI_CSV', 'CTI_NVD', 'CTI_EPSS', 'CTI_CISA_KEV',
  'WAZUH_VULNERABILITIES', 'WAZUH_ENDPOINT_CONTEXT', 'MANUAL'
);
CREATE TYPE "SyncRunStatus" AS ENUM ('RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED');
CREATE TYPE "CtiSourceStatus" AS ENUM ('DISABLED', 'READY', 'ACTIVE', 'ERROR');
CREATE TYPE "VulnerabilityLifecycleStatus" AS ENUM ('ACTIVE', 'RESOLVED', 'UNDER_EVALUATION', 'UNKNOWN');

-- The Phase 2 inventory normalizer can return longer architecture labels than
-- the original bootstrapper schema allowed.
ALTER TABLE "devices" ALTER COLUMN "architecture" TYPE VARCHAR(80);

CREATE TABLE "cti_sources" (
  "id" UUID NOT NULL,
  "code" VARCHAR(80) NOT NULL,
  "name" VARCHAR(160) NOT NULL,
  "source_type" "SyncSourceType" NOT NULL,
  "description" TEXT,
  "status" "CtiSourceStatus" NOT NULL DEFAULT 'READY',
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "last_attempt_at" TIMESTAMPTZ(3),
  "last_success_at" TIMESTAMPTZ(3),
  "last_error" TEXT,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "cti_sources_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "cves" (
  "cve_id" VARCHAR(32) NOT NULL,
  "cve_description" TEXT,
  "published_at" TIMESTAMPTZ(3),
  "modified_at" TIMESTAMPTZ(3),
  "source" VARCHAR(40) NOT NULL DEFAULT 'UNKNOWN',
  "source_version" VARCHAR(80),
  "source_document_hash" CHAR(64),
  "ingested_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "cves_pkey" PRIMARY KEY ("cve_id")
);

CREATE TABLE "cve_cvss_metrics" (
  "id" UUID NOT NULL,
  "cve_id" VARCHAR(32) NOT NULL,
  "source" VARCHAR(40) NOT NULL,
  "metric_type" VARCHAR(80) NOT NULL,
  "cvss_version" VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
  "vector_string" VARCHAR(255),
  "base_score" DOUBLE PRECISION,
  "base_severity" VARCHAR(32),
  "attack_vector" VARCHAR(40),
  "attack_complexity" VARCHAR(40),
  "privileges_required" VARCHAR(40),
  "user_interaction" VARCHAR(40),
  "scope" VARCHAR(40),
  "confidentiality_impact" VARCHAR(40),
  "integrity_impact" VARCHAR(40),
  "availability_impact" VARCHAR(40),
  "published_at" TIMESTAMPTZ(3),
  "ingested_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "cve_cvss_metrics_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "cwes" (
  "cwe_id" VARCHAR(32) NOT NULL,
  "name" VARCHAR(255),
  "description" TEXT,
  "source" VARCHAR(40) NOT NULL DEFAULT 'UNKNOWN',
  "modified_at" TIMESTAMPTZ(3),
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "cwes_pkey" PRIMARY KEY ("cwe_id")
);

CREATE TABLE "cve_cwes" (
  "cve_id" VARCHAR(32) NOT NULL,
  "cwe_id" VARCHAR(32) NOT NULL,
  "source" VARCHAR(40) NOT NULL,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "cve_cwes_pkey" PRIMARY KEY ("cve_id", "cwe_id", "source")
);

CREATE TABLE "cve_references" (
  "id" UUID NOT NULL,
  "cve_id" VARCHAR(32) NOT NULL,
  "url" TEXT NOT NULL,
  "url_hash" CHAR(64) NOT NULL,
  "source" VARCHAR(40) NOT NULL,
  "tags" JSONB,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "cve_references_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "cve_affected_products" (
  "id" UUID NOT NULL,
  "cve_id" VARCHAR(32) NOT NULL,
  "fingerprint" CHAR(64) NOT NULL,
  "vendor" VARCHAR(255),
  "product" VARCHAR(255),
  "cpe_uri" TEXT,
  "version_start_including" VARCHAR(255),
  "version_start_excluding" VARCHAR(255),
  "version_end_including" VARCHAR(255),
  "version_end_excluding" VARCHAR(255),
  "version_criteria" JSONB,
  "source" VARCHAR(40) NOT NULL,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "cve_affected_products_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "cve_threat_signals" (
  "id" UUID NOT NULL,
  "cve_id" VARCHAR(32) NOT NULL,
  "signal_date" DATE NOT NULL,
  "epss_score" DOUBLE PRECISION,
  "epss_percentile" DOUBLE PRECISION,
  "is_known_exploited" BOOLEAN NOT NULL DEFAULT false,
  "kev_date_added" DATE,
  "exploit_evidence" JSONB,
  "source_versions" JSONB,
  "ingested_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "cve_threat_signals_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "sync_runs" (
  "id" UUID NOT NULL,
  "source_id" UUID,
  "device_id" UUID,
  "source_type" "SyncSourceType" NOT NULL,
  "status" "SyncRunStatus" NOT NULL DEFAULT 'RUNNING',
  "trigger" VARCHAR(40) NOT NULL DEFAULT 'MANUAL',
  "source_version" VARCHAR(120),
  "checkpoint_before" JSONB,
  "checkpoint_after" JSONB,
  "metadata" JSONB,
  "started_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completed_at" TIMESTAMPTZ(3),
  "records_read" INTEGER NOT NULL DEFAULT 0,
  "records_written" INTEGER NOT NULL DEFAULT 0,
  "records_updated" INTEGER NOT NULL DEFAULT 0,
  "records_resolved" INTEGER NOT NULL DEFAULT 0,
  "records_rejected" INTEGER NOT NULL DEFAULT 0,
  "error_summary" TEXT,
  "source_manifest" JSONB,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "sync_runs_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "detected_vulnerabilities" (
  "id" UUID NOT NULL,
  "device_id" UUID NOT NULL,
  "cve_id" VARCHAR(32) NOT NULL,
  "sync_run_id" UUID,
  "wazuh_agent_id" VARCHAR(16) NOT NULL,
  "package_name" VARCHAR(255),
  "package_version" VARCHAR(255),
  "package_architecture" VARCHAR(80),
  "package_vendor" VARCHAR(255),
  "package_type" VARCHAR(80),
  "status" "VulnerabilityLifecycleStatus" NOT NULL DEFAULT 'ACTIVE',
  "source_status" VARCHAR(80),
  "severity" VARCHAR(32),
  "cvss_base_score" DOUBLE PRECISION,
  "detected_at" TIMESTAMPTZ(3),
  "published_at" TIMESTAMPTZ(3),
  "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "resolved_at" TIMESTAMPTZ(3),
  "source_index" VARCHAR(255) NOT NULL,
  "source_document_id" VARCHAR(512) NOT NULL,
  "source_updated_at" TIMESTAMPTZ(3),
  "raw_payload" JSONB,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "detected_vulnerabilities_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "endpoint_context_snapshots" (
  "id" UUID NOT NULL,
  "device_id" UUID NOT NULL,
  "sync_run_id" UUID,
  "wazuh_agent_id" VARCHAR(16) NOT NULL,
  "observed_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "as_of_time" TIMESTAMPTZ(3) NOT NULL,
  "agent_status" VARCHAR(40),
  "agent_ip" VARCHAR(255),
  "hostname" VARCHAR(255),
  "os_name" VARCHAR(255),
  "os_version" VARCHAR(255),
  "os_full" VARCHAR(512),
  "architecture" VARCHAR(80),
  "packages" JSONB,
  "hotfixes" JSONB,
  "ports" JSONB,
  "processes" JSONB,
  "services" JSONB,
  "system_inventory" JSONB,
  "hardware" JSONB,
  "package_count" INTEGER NOT NULL DEFAULT 0,
  "hotfix_count" INTEGER NOT NULL DEFAULT 0,
  "port_count" INTEGER NOT NULL DEFAULT 0,
  "listening_port_count" INTEGER NOT NULL DEFAULT 0,
  "process_count" INTEGER NOT NULL DEFAULT 0,
  "service_count" INTEGER NOT NULL DEFAULT 0,
  "completeness" JSONB,
  "source_versions" JSONB,
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "endpoint_context_snapshots_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "cti_sources_code_key" ON "cti_sources"("code");
CREATE INDEX "cti_sources_source_type_status_idx" ON "cti_sources"("source_type", "status");
CREATE INDEX "cves_published_at_idx" ON "cves"("published_at");
CREATE INDEX "cves_modified_at_idx" ON "cves"("modified_at");
CREATE INDEX "cves_source_ingested_at_idx" ON "cves"("source", "ingested_at");
CREATE UNIQUE INDEX "cve_cvss_metrics_identity_key" ON "cve_cvss_metrics"("cve_id", "source", "metric_type", "cvss_version");
CREATE INDEX "cve_cvss_metrics_base_severity_base_score_idx" ON "cve_cvss_metrics"("base_severity", "base_score");
CREATE INDEX "cve_cwes_cwe_id_idx" ON "cve_cwes"("cwe_id");
CREATE UNIQUE INDEX "cve_references_cve_id_url_hash_key" ON "cve_references"("cve_id", "url_hash");
CREATE INDEX "cve_references_source_idx" ON "cve_references"("source");
CREATE UNIQUE INDEX "cve_affected_products_fingerprint_key" ON "cve_affected_products"("fingerprint");
CREATE INDEX "cve_affected_products_cve_id_vendor_product_idx" ON "cve_affected_products"("cve_id", "vendor", "product");
CREATE UNIQUE INDEX "cve_threat_signals_cve_id_signal_date_key" ON "cve_threat_signals"("cve_id", "signal_date");
CREATE INDEX "cve_threat_signals_signal_date_is_known_exploited_idx" ON "cve_threat_signals"("signal_date", "is_known_exploited");
CREATE INDEX "sync_runs_source_type_started_at_idx" ON "sync_runs"("source_type", "started_at");
CREATE INDEX "sync_runs_status_started_at_idx" ON "sync_runs"("status", "started_at");
CREATE INDEX "sync_runs_device_id_started_at_idx" ON "sync_runs"("device_id", "started_at");
CREATE INDEX "sync_runs_source_id_started_at_idx" ON "sync_runs"("source_id", "started_at");
CREATE UNIQUE INDEX "detected_vulnerabilities_source_index_source_document_id_key" ON "detected_vulnerabilities"("source_index", "source_document_id");
CREATE INDEX "detected_vulnerabilities_device_id_status_severity_idx" ON "detected_vulnerabilities"("device_id", "status", "severity");
CREATE INDEX "detected_vulnerabilities_device_id_cve_id_status_idx" ON "detected_vulnerabilities"("device_id", "cve_id", "status");
CREATE INDEX "detected_vulnerabilities_cve_id_last_seen_at_idx" ON "detected_vulnerabilities"("cve_id", "last_seen_at");
CREATE INDEX "detected_vulnerabilities_sync_run_id_idx" ON "detected_vulnerabilities"("sync_run_id");
CREATE INDEX "endpoint_context_snapshots_device_id_as_of_time_idx" ON "endpoint_context_snapshots"("device_id", "as_of_time");
CREATE INDEX "endpoint_context_snapshots_sync_run_id_idx" ON "endpoint_context_snapshots"("sync_run_id");
CREATE INDEX "endpoint_context_snapshots_wazuh_agent_id_as_of_time_idx" ON "endpoint_context_snapshots"("wazuh_agent_id", "as_of_time");
CREATE INDEX "devices_status_last_seen_at_idx" ON "devices"("status", "last_seen_at");
CREATE INDEX "wazuh_agent_bindings_last_known_status_last_synchronized_at_idx" ON "wazuh_agent_bindings"("last_known_status", "last_synchronized_at");

ALTER TABLE "cve_cvss_metrics" ADD CONSTRAINT "cve_cvss_metrics_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("cve_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "cve_cwes" ADD CONSTRAINT "cve_cwes_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("cve_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "cve_cwes" ADD CONSTRAINT "cve_cwes_cwe_id_fkey" FOREIGN KEY ("cwe_id") REFERENCES "cwes"("cwe_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "cve_references" ADD CONSTRAINT "cve_references_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("cve_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "cve_affected_products" ADD CONSTRAINT "cve_affected_products_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("cve_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "cve_threat_signals" ADD CONSTRAINT "cve_threat_signals_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("cve_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "sync_runs" ADD CONSTRAINT "sync_runs_source_id_fkey" FOREIGN KEY ("source_id") REFERENCES "cti_sources"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "sync_runs" ADD CONSTRAINT "sync_runs_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "detected_vulnerabilities" ADD CONSTRAINT "detected_vulnerabilities_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "detected_vulnerabilities" ADD CONSTRAINT "detected_vulnerabilities_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cves"("cve_id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "detected_vulnerabilities" ADD CONSTRAINT "detected_vulnerabilities_sync_run_id_fkey" FOREIGN KEY ("sync_run_id") REFERENCES "sync_runs"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "endpoint_context_snapshots" ADD CONSTRAINT "endpoint_context_snapshots_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "endpoint_context_snapshots" ADD CONSTRAINT "endpoint_context_snapshots_sync_run_id_fkey" FOREIGN KEY ("sync_run_id") REFERENCES "sync_runs"("id") ON DELETE SET NULL ON UPDATE CASCADE;
