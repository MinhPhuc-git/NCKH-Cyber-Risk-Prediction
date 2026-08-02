import {
  countListeningPorts,
  normalizeContextMetadata,
  normalizeVulnerabilityDocument,
  referenceHash,
  stableHash,
} from './wazuh-state-normalizer';

describe('Wazuh state normalizer', () => {
  it('normalizes a Wazuh vulnerability state document', () => {
    const result = normalizeVulnerabilityDocument({
      index: 'wazuh-states-vulnerabilities-test',
      id: 'doc-1',
      source: {
        agent: { id: '001', name: 'endpoint-1' },
        package: {
          name: 'example-package',
          version: '1.2.3',
          architecture: 'x86_64',
          vendor: 'Example Vendor',
          type: 'deb',
        },
        vulnerability: {
          id: 'CVE-2026-12345',
          description: 'Example vulnerability',
          severity: 'important',
          status: 'active',
          detected_at: '2026-07-12T12:00:00.000Z',
          published_at: '2026-07-01T00:00:00.000Z',
          reference: [
            'https://example.test/advisory',
            'https://example.test/advisory',
            'not-a-url',
          ],
          score: {
            base: 8.8,
            version: '3.1',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
          },
        },
        wazuh: { schema: { version: '1.0.0' } },
      },
    });

    expect(result).not.toBeNull();
    expect(result).toMatchObject({
      sourceIndex: 'wazuh-states-vulnerabilities-test',
      sourceDocumentId: 'doc-1',
      cveId: 'CVE-2026-12345',
      packageName: 'example-package',
      packageVersion: '1.2.3',
      severity: 'HIGH',
      status: 'ACTIVE',
      cvssBaseScore: 8.8,
      cvssVersion: '3.1',
      attackVector: 'NETWORK',
      attackComplexity: 'LOW',
      privilegesRequired: 'LOW',
      userInteraction: 'NONE',
      scope: 'UNCHANGED',
      confidentialityImpact: 'HIGH',
      integrityImpact: 'HIGH',
      availabilityImpact: 'HIGH',
      schemaVersion: '1.0.0',
      references: ['https://example.test/advisory'],
    });
  });

  it('rejects documents without a valid CVE identifier', () => {
    expect(
      normalizeVulnerabilityDocument({
        index: 'wazuh-states-vulnerabilities-test',
        id: 'doc-invalid',
        source: { vulnerability: { id: 'GHSA-example' } },
      }),
    ).toBeNull();
  });

  it('normalizes context metadata with agent fallbacks', () => {
    const metadata = normalizeContextMetadata(
      [
        {
          index: 'wazuh-states-inventory-system-test',
          id: 'system-1',
          source: {
            host: {
              hostname: 'workstation-01',
              architecture: 'x86_64',
              os: {
                name: 'Windows',
                version: '11',
                full: 'Windows 11 Pro',
              },
            },
            wazuh: { schema: { version: '1.2.0' } },
          },
        },
      ],
      {
        id: '001',
        name: 'agent-fallback',
        os: { name: 'Fallback OS', arch: 'amd64' },
      },
    );

    expect(metadata).toEqual({
      hostname: 'workstation-01',
      osName: 'Windows',
      osVersion: '11',
      osFull: 'Windows 11 Pro',
      architecture: 'x86_64',
      schemaVersion: '1.2.0',
    });
  });

  it('counts listening ports while tolerating missing state', () => {
    expect(
      countListeningPorts([
        { network: { state: 'LISTEN', local: { port: 443 } } },
        { network: { state: 'ESTABLISHED', local: { port: 50000 } } },
        { local_port: 22 },
        { network: { state: 'LISTEN' } },
      ]),
    ).toBe(2);
  });

  it('creates stable hashes independent of object key order', () => {
    expect(stableHash({ a: 1, b: 2 })).toBe(stableHash({ b: 2, a: 1 }));
    expect(referenceHash('https://example.test')).toHaveLength(64);
  });
});
