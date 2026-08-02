from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path

from src.identity import load_or_create_identity


class IdentityTests(unittest.TestCase):
    def test_identity_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_directory = Path(temporary_directory)

            first = load_or_create_identity(data_directory)
            second = load_or_create_identity(data_directory)

            self.assertEqual(first, second)
            uuid.UUID(first["installationId"])


if __name__ == "__main__":
    unittest.main()
