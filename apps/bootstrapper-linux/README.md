# CYRP Linux Wazuh Agent migration bootstrapper

This directory contains the endpoint-side scripts for replacing an existing
Linux Wazuh Agent identity with the one automatically provisioned by CYRP
Phase 2B.1.

For the current lab:

- Existing identity: Agent `002`, name `ch3`
- Target identity: Agent `003`, name similar to `cyrp-9f673dfd409d`
- Wazuh Manager: `192.168.100.247:1514/tcp`

The Wazuh Agent package is already installed on the Ubuntu VM. This phase does
not reinstall it. It backs up `ossec.conf` and `client.keys`, imports the
Phase 2B.1 client key with `manage_agents`, configures the Manager, restarts
`wazuh-agent`, and verifies `status='connected'`.

The Windows transfer helper decrypts the existing DPAPI `.clixml` under the
same Windows account that created it, transfers a temporary owner-only JSON
file over SSH, and deletes the local plaintext copy immediately. The Linux
installer deletes the remote JSON after a successful migration.

Do not print, commit, or share the JSON enrollment file.
