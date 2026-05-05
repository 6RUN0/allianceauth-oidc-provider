from .celery import app as celery_app

# Note: OIDCTestCase is intentionally NOT re-exported here. Importing it would
# pull Django/Alliance Auth model classes at package import time, which Django's
# test runner does before django.setup() and causes AppRegistryNotReady.
# Test modules should import it directly:
#     from ._oidc_testcase import OIDCTestCase

__all__ = ["celery_app"]
