-- CreateEnum
CREATE TYPE "DeviceStatus" AS ENUM ('OFFLINE', 'IDLE', 'SCANNING', 'ERROR');

-- CreateTable
CREATE TABLE "devices" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "installation_id" VARCHAR(64) NOT NULL,
    "hostname" VARCHAR(255) NOT NULL,
    "operating_system" VARCHAR(255) NOT NULL,
    "architecture" VARCHAR(50),
    "agent_version" VARCHAR(30) NOT NULL,
    "status" "DeviceStatus" NOT NULL DEFAULT 'OFFLINE',
    "last_seen_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_credentials" (
    "id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked_at" TIMESTAMPTZ(3),

    CONSTRAINT "agent_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_enrollment_codes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "code_hash" CHAR(64) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_enrollment_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "devices_installation_id_key" ON "devices"("installation_id");

-- CreateIndex
CREATE INDEX "devices_user_id_idx" ON "devices"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "agent_credentials_device_id_key" ON "agent_credentials"("device_id");

-- CreateIndex
CREATE UNIQUE INDEX "agent_credentials_token_hash_key" ON "agent_credentials"("token_hash");

-- CreateIndex
CREATE UNIQUE INDEX "device_enrollment_codes_code_hash_key" ON "device_enrollment_codes"("code_hash");

-- CreateIndex
CREATE INDEX "device_enrollment_codes_user_id_expires_at_idx" ON "device_enrollment_codes"("user_id", "expires_at");

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_credentials" ADD CONSTRAINT "agent_credentials_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_enrollment_codes" ADD CONSTRAINT "device_enrollment_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
