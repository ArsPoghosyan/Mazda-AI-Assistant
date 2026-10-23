"""Build the fixed Supabase Google authorization destination without network I/O."""

import re
from urllib.parse import urlencode

from app.account_oauth_material import InvalidOAuthLoginMaterial
from app.config import Settings


class GoogleAuthorizationUnavailable(RuntimeError):
    """The fixed authorization destination is not configured."""


def build_google_authorization_url(settings: Settings, code_challenge: str) -> str:
    """Accept only a generated S256 challenge, never browser redirect/provider options.

    Supabase owns its upstream OAuth state. No verifier, cookie token, API key or
    provider token belongs in this URL. The caller owns pending-attempt commit
    and navigation; this function neither enables login nor contacts Supabase.
    """
    issuer = settings.supabase_auth_issuer
    callback = settings.account_google_oauth_callback_url
    if issuer is None or callback is None:
        raise GoogleAuthorizationUnavailable("Google sign-in is unavailable.")
    if len(code_challenge) != 43 or re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge) is None:
        raise InvalidOAuthLoginMaterial("Invalid OAuth login material.")

    # Wire spelling matches Supabase Auth's own client (S256 algorithm).
    query = urlencode(
        {
            "provider": "google",
            "redirect_to": str(callback),
            "code_challenge": code_challenge,
            "code_challenge_method": "s256",
        }
    )
    return f"{issuer}/authorize?{query}"
