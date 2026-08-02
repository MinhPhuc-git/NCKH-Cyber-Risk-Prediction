from __future__ import annotations

import ctypes
import getpass
import os
import sys
from typing import Any


def get_current_privileges() -> dict[str, Any]:
    username = os.environ.get("USERNAME") or getpass.getuser() or "Unknown"

    result: dict[str, Any] = {
        "username": username,
        "isAdmin": False,
        "privilegeLevel": "LOW",
        "platformSupported": sys.platform == "win32",
    }

    if sys.platform != "win32":
        result["error"] = "Collector chỉ hỗ trợ Windows"
        return result

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        result["isAdmin"] = is_admin
        result["privilegeLevel"] = "HIGH" if is_admin else "LOW"
    except Exception as error:
        result["privilegeLevel"] = "UNKNOWN"
        result["error"] = str(error)

    return result
