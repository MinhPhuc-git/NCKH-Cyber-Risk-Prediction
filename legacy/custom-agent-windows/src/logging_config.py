from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOGGER_NAME = "cyrp_agent"


def close_logger_handlers(logger: logging.Logger) -> None:
    """Flush, close, and detach every handler from the logger."""
    for handler in logger.handlers[:]:
        try:
            handler.flush()
        finally:
            handler.close()
            logger.removeHandler(handler)


def _has_expected_file_handler(
    logger: logging.Logger,
    log_file: Path,
) -> bool:
    expected_path = log_file.resolve()

    for handler in logger.handlers:
        if not isinstance(handler, RotatingFileHandler):
            continue

        current_path = Path(handler.baseFilename).resolve()

        if current_path == expected_path:
            return True

    return False


def configure_logging(
    log_directory: Path,
    verbose: bool = False,
    *,
    force_reconfigure: bool = False,
) -> logging.Logger:
    log_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_file = log_directory / "agent.log"
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(
        logging.DEBUG
        if verbose
        else logging.INFO
    )
    logger.propagate = False

    must_reconfigure = (
        force_reconfigure
        or (
            bool(logger.handlers)
            and not _has_expected_file_handler(
                logger,
                log_file,
            )
        )
    )

    if must_reconfigure:
        close_logger_handlers(logger)

    if logger.handlers:
        for handler in logger.handlers:
            if isinstance(
                handler,
                logging.StreamHandler,
            ) and not isinstance(
                handler,
                RotatingFileHandler,
            ):
                handler.setLevel(
                    logging.DEBUG
                    if verbose
                    else logging.INFO
                )

        return logger

    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s | %(levelname)s | "
            "%(name)s | %(message)s"
        ),
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setLevel(
        logging.DEBUG
        if verbose
        else logging.INFO
    )
    console.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console)
    logger.addHandler(file_handler)

    return logger
