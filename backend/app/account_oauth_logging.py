"""Redact OAuth callback queries from standard Uvicorn access records."""

import logging

_CALLBACK_PATH = "/api/v1/account/google/callback"


class OAuthCallbackAccessFilter(logging.Filter):
    """Keep request method/path/status while removing callback query values.

    Uvicorn's h11 and httptools access records contain five positional fields.
    This does not configure reverse-proxy, hosting or custom request logging.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        arguments = record.args
        if isinstance(arguments, tuple) and len(arguments) == 5:
            target = arguments[2]
            if isinstance(target, str):
                path = target.partition("?")[0]
                if path.rstrip("/").endswith(_CALLBACK_PATH) or f"{_CALLBACK_PATH}/" in path:
                    record.args = (*arguments[:2], path, *arguments[3:])
        return True


def install_oauth_access_log_filter() -> None:
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, OAuthCallbackAccessFilter) for item in logger.filters):
        logger.addFilter(OAuthCallbackAccessFilter())
