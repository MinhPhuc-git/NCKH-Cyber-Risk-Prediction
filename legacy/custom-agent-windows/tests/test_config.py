from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.config import load_config


class ConfigTests(unittest.TestCase):
    def test_loads_valid_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "agent": {
                            "version": "0.1.0",
                            "schemaVersion": "1.0",
                            "dataDirectory": str(root / "data"),
                            "logDirectory": str(root / "logs"),
                            "system32FileLimit": 10,
                            "system32Recursive": False,
                            "powershellTimeoutSeconds": 5,
                            "maxNetworkConnections": 20,
                            "monitoredPorts": [445, 3389, 445],
                        },
                        "server": {
                            "baseUrl": "http://127.0.0.1:3001/api/v1/",
                            "requestTimeoutSeconds": 10,
                            "pollIntervalSeconds": 3,
                            "longPollSeconds": 20,
                        },
                    }
                ),
                encoding="utf-8",
            )

            config = load_config(config_path)

            self.assertEqual(config.agent.version, "0.1.0")
            self.assertEqual(config.agent.monitored_ports, (445, 3389))
            self.assertEqual(config.server.base_url, "http://127.0.0.1:3001/api/v1")
            self.assertTrue(config.agent.data_directory.exists())
            self.assertTrue(config.agent.log_directory.exists())


if __name__ == "__main__":
    unittest.main()
