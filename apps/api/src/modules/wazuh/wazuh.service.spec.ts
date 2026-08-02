import { WazuhService } from './wazuh.service';

describe('WazuhService', () => {
  it('is defined with API and Indexer settings', () => {
    const config = {
      get: jest.fn(
        (name: string) => {
          const values:
            Record<string, string> = {
            WAZUH_INTEGRATION_ENABLED:
              'true',
            NODE_ENV: 'test',
            WAZUH_API_BASE_URL:
              'https://127.0.0.1:55000',
            WAZUH_API_USERNAME:
              'wazuh',
            WAZUH_API_PASSWORD:
              'password',
            WAZUH_API_REJECT_UNAUTHORIZED:
              'false',
            WAZUH_API_TIMEOUT_MS:
              '10000',
            WAZUH_API_TOKEN_TTL_SECONDS:
              '900',
            WAZUH_INDEXER_BASE_URL:
              'https://127.0.0.1:19201',
            WAZUH_INDEXER_USERNAME:
              'admin',
            WAZUH_INDEXER_PASSWORD:
              'password',
            WAZUH_INDEXER_REJECT_UNAUTHORIZED:
              'false',
            WAZUH_INDEXER_TIMEOUT_MS:
              '15000',
            WAZUH_ALERT_SAMPLE_LIMIT:
              '10',
            WAZUH_MAX_RESPONSE_BYTES:
              '5242880',
          };

          return values[name];
        },
      ),
    };

    const service =
      new WazuhService(
        config as never,
      );

    expect(service).toBeDefined();
    expect(service.getRuntimeConfiguration()).toMatchObject({
      enabled: true,
      retryAttempts: 3,
      retryBaseDelayMs: 250,
      statePageSize: 250,
      stateMaxItems: 5000,
    });
  });

  it('accepts Joi-coerced boolean and numeric configuration values', () => {
    const config = {
      get: jest.fn((name: string) => {
        const values: Record<string, unknown> = {
          WAZUH_INTEGRATION_ENABLED: true,
          WAZUH_API_BASE_URL: 'https://127.0.0.1:55000',
          WAZUH_API_USERNAME: 'wazuh',
          WAZUH_API_PASSWORD: 'password',
          WAZUH_API_REJECT_UNAUTHORIZED: false,
          WAZUH_API_TIMEOUT_MS: 10000,
          WAZUH_INDEXER_BASE_URL: 'https://127.0.0.1:9200',
          WAZUH_INDEXER_USERNAME: 'readonly',
          WAZUH_INDEXER_PASSWORD: 'password',
          WAZUH_INDEXER_REJECT_UNAUTHORIZED: false,
          WAZUH_INDEXER_TIMEOUT_MS: 15000,
          WAZUH_AGENT_MANAGER_PORT: 1514,
          WAZUH_REQUEST_RETRY_ATTEMPTS: 4,
          WAZUH_REQUEST_RETRY_BASE_DELAY_MS: 500,
        };

        return values[name];
      }),
    };

    const service = new WazuhService(config as never);

    expect(service.getRuntimeConfiguration()).toMatchObject({
      enabled: true,
      retryAttempts: 4,
      retryBaseDelayMs: 500,
    });
  });
});
