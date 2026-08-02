import * as Joi from 'joi';

const booleanString = Joi.boolean()
  .truthy('true')
  .falsy('false');

const httpUrl = Joi.string().uri({
  scheme: ['http', 'https'],
});

export const validationSchema = Joi.object({
  AI_MODEL_ENABLED: Joi.string().valid('true', 'false').optional(),
  AI_MODEL_ACTIVE: Joi.string().trim().optional(),
  AI_MODEL_VERSION: Joi.string().trim().optional(),
  AI_MODEL_PYTHON_PATH: Joi.string().trim().optional(),
  AI_MODEL_PREDICT_SCRIPT: Joi.string().trim().optional(),
  AI_MODEL_RUNTIME_DIR: Joi.string().trim().optional(),
  AI_MODEL_TIMEOUT_MS: Joi.number().integer().min(1000).optional(),

  AI_PIPELINE_MODEL_ROOT: Joi.string().trim().optional(),
  AI_PIPELINE_DATA_USER_DIR: Joi.string().trim().optional(),
  AI_PIPELINE_PYTHON_PATH: Joi.string().trim().optional(),
  AI_PIPELINE_TIMEOUT_MS: Joi.number().integer().min(1000).optional(),

  CTI_CVSS_ENRICHMENT_ENABLED: booleanString.default(true),
  CTI_CVSS_PYTHON_PATH: Joi.string().trim().optional(),
  CTI_CVSS_ENRICHMENT_SCRIPT: Joi.string().trim().optional(),
  CTI_CVSS_DATASET_PATH: Joi.string().trim().optional(),
  CTI_CVSS_ENRICHMENT_TIMEOUT_MS: Joi.number()
    .integer()
    .min(5000)
    .max(300000)
    .default(30000),

  MACHINE_CHECK_FRESHNESS_SECONDS: Joi.number()
    .integer()
    .min(0)
    .max(3600)
    .default(300),
  MACHINE_CHECK_POLL_INTERVAL_MS: Joi.number()
    .integer()
    .min(500)
    .max(10000)
    .default(2000),

  WAZUH_INDEXER_USERNAME: Joi.string().trim().optional(),
  WAZUH_INDEXER_PASSWORD: Joi.string().trim().optional(),
  WAZUH_INDEXER_REJECT_UNAUTHORIZED: Joi.string().valid('true', 'false').optional(),

  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  API_HOST: Joi.string().default('0.0.0.0'),
  API_PORT: Joi.number().integer().min(1).max(65535).default(3001),
  CORS_ORIGINS: Joi.string().default(
    'http://localhost:3000,http://localhost:3002',
  ),
  SWAGGER_ENABLED: booleanString.optional(),

  POSTGRES_PORT: Joi.number().integer().min(1).max(65535).default(5432),
  POSTGRES_USER: Joi.string().required(),
  POSTGRES_PASSWORD: Joi.string().required(),
  POSTGRES_DB: Joi.string().required(),
  DATABASE_URL: Joi.string()
    .uri({ scheme: ['postgresql', 'postgres'] })
    .required(),

  JWT_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRES_IN: Joi.string()
    .pattern(/^\d+[smhd]$/)
    .default('15m'),

  WAZUH_INTEGRATION_ENABLED: booleanString.default(false),

  WAZUH_API_BASE_URL: httpUrl.when(
    'WAZUH_INTEGRATION_ENABLED',
    {
      is: true,
      then: Joi.required(),
      otherwise: Joi.optional(),
    },
  ),
  WAZUH_API_USERNAME: Joi.string()
    .trim()
    .min(1)
    .when('WAZUH_INTEGRATION_ENABLED', {
      is: true,
      then: Joi.required(),
      otherwise: Joi.optional(),
    }),
  WAZUH_API_PASSWORD: Joi.string()
    .min(1)
    .when('WAZUH_INTEGRATION_ENABLED', {
      is: true,
      then: Joi.required(),
      otherwise: Joi.optional(),
    }),
  WAZUH_API_REJECT_UNAUTHORIZED: booleanString.default(true),
  WAZUH_API_TIMEOUT_MS: Joi.number().integer().min(1000).default(10000),
  WAZUH_API_TOKEN_TTL_SECONDS: Joi.number().integer().min(60).default(900),

  WAZUH_INDEXER_BASE_URL: httpUrl.when(
    'WAZUH_INTEGRATION_ENABLED',
    {
      is: true,
      then: Joi.required(),
      otherwise: Joi.optional(),
    },
  ),
  WAZUH_INDEXER_TIMEOUT_MS: Joi.number().integer().min(1000).default(15000),
  WAZUH_ALERT_SAMPLE_LIMIT: Joi.number().integer().min(1).max(100).default(10),
  WAZUH_STATE_PAGE_SIZE: Joi.number().integer().min(25).max(1000).default(250),
  WAZUH_STATE_MAX_ITEMS_PER_CATEGORY: Joi.number()
    .integer()
    .min(100)
    .max(10000)
    .default(5000),
  WAZUH_MAX_RESPONSE_BYTES: Joi.number()
    .integer()
    .min(65536)
    .max(104857600)
    .default(10485760),
  WAZUH_REQUEST_RETRY_ATTEMPTS: Joi.number()
    .integer()
    .min(1)
    .max(5)
    .default(3),
  WAZUH_REQUEST_RETRY_BASE_DELAY_MS: Joi.number()
    .integer()
    .min(50)
    .max(5000)
    .default(250),

  WAZUH_AGENT_MANAGER_ADDRESS: Joi.string().trim().max(255).optional(),
  WAZUH_AGENT_MANAGER_PORT: Joi.number()
    .integer()
    .min(1)
    .max(65535)
    .default(1514),
  WAZUH_AGENT_MANAGER_PROTOCOL: Joi.string()
    .valid('tcp', 'udp')
    .default('tcp'),

  WAZUH_ACTIVE_SYNC_ENABLED: booleanString.default(false),
  WAZUH_ACTIVE_SYNC_INTERVAL_SECONDS: Joi.number()
    .integer()
    .min(60)
    .default(300),
  WAZUH_ACTIVE_SYNC_WINDOW_MINUTES: Joi.number()
    .integer()
    .min(15)
    .default(1440),
  WAZUH_ACTIVE_SYNC_MAX_CONCURRENCY: Joi.number()
    .integer()
    .min(1)
    .max(8)
    .default(2),

  WAZUH_DATA_SYNC_ENABLED: booleanString.default(false),
  WAZUH_DATA_SYNC_INTERVAL_SECONDS: Joi.number()
    .integer()
    .min(300)
    .default(900),
  WAZUH_DATA_SYNC_MAX_CONCURRENCY: Joi.number()
    .integer()
    .min(1)
    .max(8)
    .default(1),
  WAZUH_INVENTORY_CATEGORY_CONCURRENCY: Joi.number()
    .integer()
    .min(1)
    .max(4)
    .default(2),
  WAZUH_DATA_SYNC_LOCK_TTL_SECONDS: Joi.number()
    .integer()
    .min(60)
    .max(3600)
    .default(900),
  WAZUH_DATA_SYNC_STALE_RUN_MINUTES: Joi.number()
    .integer()
    .min(5)
    .max(1440)
    .default(30),

  WAZUH_AGENT_STATUS_SYNC_ENABLED: booleanString.default(false),
  WAZUH_AGENT_STATUS_SYNC_INTERVAL_SECONDS: Joi.number()
    .integer()
    .min(60)
    .max(86400)
    .default(300),
  WAZUH_AGENT_STATUS_SYNC_MAX_CONCURRENCY: Joi.number()
    .integer()
    .min(1)
    .max(16)
    .default(4),


});
