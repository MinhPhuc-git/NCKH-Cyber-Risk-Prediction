process.env.NODE_ENV = 'test';

process.env.API_HOST = '0.0.0.0';
process.env.API_PORT = '3001';
process.env.CORS_ORIGINS = 'http://localhost:3000';

process.env.POSTGRES_HOST = 'localhost';
process.env.POSTGRES_PORT = '5432';
process.env.POSTGRES_USER = 'cyrp';
process.env.POSTGRES_PASSWORD =
  'change_me_for_local_development';
process.env.POSTGRES_DB = 'cyrp';

process.env.DATABASE_URL =
  'postgresql://cyrp:change_me_for_local_development@localhost:5432/cyrp?schema=public';
process.env.WAZUH_INTEGRATION_ENABLED = 'false';
process.env.WAZUH_ACTIVE_SYNC_ENABLED = 'false';
process.env.WAZUH_DATA_SYNC_ENABLED = 'false';
process.env.SWAGGER_ENABLED = 'false';
