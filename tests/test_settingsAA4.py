"""Alliance Auth Test Suite Django settings."""

# Activate the fakeredis monkey-patch BEFORE importing any AA module —
# AppConfig.ready() in allianceauth.* talks to Redis on startup. Settings
# module-level is the earliest hook available to us.
from tests._fakeredis import install_if_enabled

install_if_enabled()

from pathlib import Path  # noqa: E402

from allianceauth.project_template.project_name.settings.base import *  # noqa: E402, F403

# NOTE: DOT does NOT auto-import PKCE_REQUIRED from a dotted-path
# string — `PKCE_REQUIRED` is not in DOT's IMPORT_STRINGS tuple
# (oauth2_provider/settings.py). Assign the function object directly;
# DOT's is_pkce_required (oauth2_validators.py) detects callables and
# dispatches per-request. Import from ``allianceauth_oidc.pkce`` (not
# ``auth_provider``) because settings are loaded before
# ``apps.populate()`` and ``auth_provider`` transitively imports DOT
# model classes.
from allianceauth_oidc.pkce import per_app_pkce_required  # noqa: E402

SITE_URL = "https://example.com"
CSRF_TRUSTED_ORIGINS = [SITE_URL]

ALLIANCEAUTH_DASHBOARD_TASK_STATISTICS_DISABLED = True

# Celery configuration
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"

INSTALLED_APPS += ["allianceauth_oidc", "oauth2_provider"]  # type: ignore[name-defined] # noqa F405

ROOT_URLCONF = "tests.urls"

NOSE_ARGS: list[str] = [
    # '--with-coverage',
    # '--cover-package=',
    # '--exe',  # If your tests need this to be found/run, check they py files are not chmodded +x
]


PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# LOGGING = None  # Comment out to enable logging for debugging

# Register an application at https://developers.eveonline.com for Authentication
# & API Access and fill out these settings. Be sure to set the callback URL
# to https://example.com/sso/callback substituting your domain for example.com
# Logging in to auth requires the publicData scope (can be overridden through the
# LOGIN_TOKEN_SCOPES setting). Other apps may require more (see their docs).
ESI_SSO_CLIENT_ID = "123"
ESI_SSO_CLIENT_SECRET = "123"  # nosec B105
ESI_SSO_CALLBACK_URL = "123"
ESI_USER_CONTACT_EMAIL = "email@dummy.com"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "allianceauth-oidc-test-cache",
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.db"

OAUTH2_PROVIDER_APPLICATION_MODEL = "allianceauth_oidc.AllianceAuthApplication"
OAUTH2_PROVIDER = {
    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": Path(
        Path(__file__).parent / "oidc-test.key"
    ).read_text(),
    "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
    "SCOPES": {"openid": "openid", "email": "email", "profile": "profile"},
    "PKCE_REQUIRED": per_app_pkce_required,
    "APPLICATION_ADMIN_CLASS": "allianceauth_oidc.admin.ApplicationAdmin",
    "ACCESS_TOKEN_EXPIRE_SECONDS": 60,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 7 * 24 * 60 * 60,
    "ROTATE_REFRESH_TOKEN": True,  # nosec B105
}
