"""Callback credentials are omitted from standard Uvicorn access logging."""

import io
import logging

import pytest
from uvicorn.logging import AccessFormatter

from app.account_oauth_logging import OAuthCallbackAccessFilter, install_oauth_access_log_filter
from app.main import create_app

PATH = "/api/v1/account/google/callback"
MESSAGE = '%s - "%s %s HTTP/%s" %d'


@pytest.mark.parametrize("path", [PATH, PATH + "/", PATH + "//", PATH + "/extra", "/prefix" + PATH])
@pytest.mark.parametrize(
    "query", ["code=synthetic-private", "error=denied&error_description=synthetic-private"]
)
def test_callback_query_is_removed_before_formatting(path: str, query: str) -> None:
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        MESSAGE,
        ("127.0.0.1:1234", "GET", path + "?" + query, "1.1", 303),
        None,
    )
    assert OAuthCallbackAccessFilter().filter(record)
    message = record.getMessage()
    assert "synthetic-private" not in message
    assert "?" not in message
    assert path in message
    formatter = AccessFormatter("%(request_line)s %(status_code)s", use_colors=False)
    formatted = formatter.format(record)
    assert "synthetic-private" not in formatted
    assert f"GET {path} HTTP/1.1" in formatted


@pytest.mark.parametrize("arguments", [(), ("one",), ("a", "GET", None, "1.1", 200)])
def test_unrelated_record_shapes_are_not_dropped_or_modified(arguments: tuple[object, ...]) -> None:
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, "message", arguments, None
    )
    assert OAuthCallbackAccessFilter().filter(record)
    assert record.args == arguments


def test_non_callback_access_record_is_preserved() -> None:
    args = ("127.0.0.1:1", "GET", "/api/v1/health?probe=yes", "1.1", 200)
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, MESSAGE, args, None)
    assert OAuthCallbackAccessFilter().filter(record)
    assert record.args == args


def test_app_factory_installs_filter_once_and_logger_emits_no_query() -> None:
    logger = logging.getLogger("uvicorn.access")
    create_app()
    create_app()
    install_oauth_access_log_filter()
    assert sum(isinstance(item, OAuthCallbackAccessFilter) for item in logger.filters) == 1
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.info(MESSAGE, "127.0.0.1:1", "GET", PATH + "?code=synthetic-private", "1.1", 303)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    assert PATH in output.getvalue()
    assert "synthetic-private" not in output.getvalue()
