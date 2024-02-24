from saml2.authn_context import INTERNETPROTOCOLPASSWORD, UNSPECIFIED
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from ..config import get_app_settings
settings = get_app_settings()

BASE = 'http://%s:%s' % (settings.host, settings.port)

authn_broker: AuthnBroker = AuthnBroker()
authn_broker.add(
  authn_context_class_ref(UNSPECIFIED),
  '',
  0,
  BASE
)