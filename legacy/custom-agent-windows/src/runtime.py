from __future__ import annotations

import argparse
import json
import logging
import signal
import time
from typing import Any

from .api_client import (
    ApiClient,
    ApiClientError,
)
from .collector import (
    collect_agent_data,
    save_scan_payload,
)
from .config import (
    AppConfig,
    load_config,
    public_config,
)
from .enrollment import (
    EnrollmentError,
    enroll_agent,
    enrollment_status,
)
from .identity import load_credentials
from .logging_config import (
    configure_logging,
)


class AgentRuntime:
    def __init__(
        self,
        config: AppConfig,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.logger = logger
        self.api = ApiClient(
            config.server,
        )
        self.running = True

    def stop(
        self,
        *_: Any,
    ) -> None:
        self.logger.info(
            "Stopping agent runtime"
        )
        self.running = False

    def scan_once(
        self,
        *,
        scan_id: str | None = None,
        device_id: str | None = None,
        skip_system32: bool = False,
        print_json: bool = False,
    ) -> dict[str, Any]:
        payload = collect_agent_data(
            self.config,
            scan_id=scan_id,
            device_id=device_id,
            skip_system32=skip_system32,
            logger=self.logger,
        )

        saved_path = save_scan_payload(
            self.config,
            payload,
        )

        self.logger.info(
            "Payload saved at %s",
            saved_path,
        )

        if print_json:
            print(
                json.dumps(
                    payload,
                    indent=2,
                    ensure_ascii=False,
                )
            )

        return payload

    def enroll(
        self,
        enrollment_code: str,
    ) -> dict[str, str]:
        self.logger.info(
            "Starting device enrollment"
        )

        result = enroll_agent(
            self.config,
            self.api,
            enrollment_code,
        )

        self.logger.info(
            "Enrollment completed for "
            "device %s",
            result["deviceId"],
        )

        return result

    def poll(self) -> None:
        credentials = load_credentials(
            self.config
            .agent
            .data_directory
        )

        device_id = credentials[
            "deviceId"
        ]

        agent_token = credentials[
            "agentToken"
        ]

        signal.signal(
            signal.SIGINT,
            self.stop,
        )

        if hasattr(
            signal,
            "SIGTERM",
        ):
            signal.signal(
                signal.SIGTERM,
                self.stop,
            )

        self.logger.info(
            "Agent is idle and waiting "
            "for scan jobs"
        )

        while self.running:
            try:
                self.api.heartbeat(
                    agent_token,
                    device_id,
                    "IDLE",
                )

                task = (
                    self.api
                    .poll_next_task(
                        agent_token,
                        device_id,
                    )
                )

                if not task:
                    continue

                if not isinstance(
                    task,
                    dict,
                ):
                    self.logger.warning(
                        "Ignored invalid "
                        "task response"
                    )
                    continue

                task_type = task.get(
                    "type"
                )

                scan_id = task.get(
                    "scanId"
                )

                if (
                    task_type
                    != "SYSTEM_SCAN"
                    or not isinstance(
                        scan_id,
                        str,
                    )
                ):
                    self.logger.warning(
                        "Ignored unsupported "
                        "task: %r",
                        task_type,
                    )
                    continue

                self.logger.info(
                    "Received system "
                    "scan job %s",
                    scan_id,
                )

                self.api.heartbeat(
                    agent_token,
                    device_id,
                    "SCANNING",
                )

                payload = self.scan_once(
                    scan_id=scan_id,
                    device_id=device_id,
                )

                self.api.heartbeat(
                    agent_token,
                    device_id,
                    "UPLOADING",
                )

                self.api.submit_scan_result(
                    agent_token,
                    scan_id,
                    payload,
                )

                self.api.heartbeat(
                    agent_token,
                    device_id,
                    "IDLE",
                )

                self.logger.info(
                    "Uploaded scan "
                    "result %s",
                    scan_id,
                )
            except ApiClientError as error:
                self.logger.warning(
                    "Server communication "
                    "failed: %s",
                    error,
                )

                time.sleep(
                    self.config
                    .server
                    .poll_interval_seconds
                )
            except Exception:
                self.logger.exception(
                    "Unexpected runtime error"
                )

                time.sleep(
                    self.config
                    .server
                    .poll_interval_seconds
                )


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "CYRP Windows Agent runtime"
        )
    )

    parser.add_argument(
        "mode",
        choices=(
            "scan-once",
            "enroll",
            "status",
            "poll",
            "show-config",
        ),
        nargs="?",
        default="scan-once",
    )

    parser.add_argument(
        "--config",
        default=None,
    )

    parser.add_argument(
        "--enrollment-code",
        default=None,
    )

    parser.add_argument(
        "--scan-id",
        default=None,
    )

    parser.add_argument(
        "--device-id",
        default=None,
    )

    parser.add_argument(
        "--skip-system32",
        action="store_true",
    )

    parser.add_argument(
        "--print-json",
        action="store_true",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)

    config = load_config(
        arguments.config,
    )

    logger = configure_logging(
        config.agent.log_directory,
        arguments.verbose,
    )

    runtime = AgentRuntime(
        config,
        logger,
    )

    if arguments.mode == "show-config":
        print(
            json.dumps(
                public_config(config),
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if arguments.mode == "status":
        print(
            json.dumps(
                enrollment_status(config),
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if arguments.mode == "enroll":
        if not arguments.enrollment_code:
            parser.error(
                "--enrollment-code "
                "là bắt buộc ở mode enroll"
            )

        try:
            result = runtime.enroll(
                arguments.enrollment_code,
            )
        except (
            ApiClientError,
            EnrollmentError,
            OSError,
            ValueError,
        ) as error:
            logger.error(
                "Enrollment failed: %s",
                error,
            )
            return 1

        print(
            "Enrollment completed"
        )

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
        )

        return 0

    if arguments.mode == "scan-once":
        runtime.scan_once(
            scan_id=arguments.scan_id,
            device_id=arguments.device_id,
            skip_system32=(
                arguments
                .skip_system32
            ),
            print_json=(
                arguments
                .print_json
            ),
        )
        return 0

    runtime.poll()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
