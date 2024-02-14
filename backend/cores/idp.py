from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.httputil import get_post
from saml2.sigver import encrypt_cert_from_item
from saml2.authn_context import INTERNETPROTOCOLPASSWORD, UNSPECIFIED
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from fastapi import HTTPException
import logging
from config import get_settings

settings = get_settings()
logger = logging.getLogger('saml2.idp')

BASE = 'http://%s:%s' % (settings.host, settings.port)

authn_broker: AuthnBroker = None
authn_broker = AuthnBroker()
authn_broker.add(
  authn_context_class_ref(UNSPECIFIED),
  '',
  0,
  BASE
)

class IdPRequest:
  def __init__(self, user=None) -> None:
    self.settings = get_settings()
    self.user = user
    
  def redirect(self, query_json: dict):
    """Expects a HTTP-redirect request"""
    return self.operation(query_json, BINDING_HTTP_REDIRECT)

  def post(self, body_json: dict):
    """Expects a HTTP-POST request"""
    return self.operation(body_json, BINDING_HTTP_POST)

  def operation(self, saml_msg, binding):
    logger.debug('_operation: %s', saml_msg)
    if not (saml_msg and 'SAMLRequest' in saml_msg):
      return HTTPException(
        status_code=404,
        detail='Error parsing request or no request')
    else:
      # saml_msg may also contain Signature and SigAlg
      if 'Signature' in saml_msg:
        try:
          kwargs = {
            'signature': saml_msg['Signature'],
            'sigalg': saml_msg['SigAlg'],
          }
        except KeyError:
          return HTTPException(
            status_code=404,
            detail='Signature Algorithm specification is missing')
      else:
        kwargs = {}

      try:
        kwargs['encrypt_cert'] = encrypt_cert_from_item(saml_msg['req_info'].message)
      except KeyError:
        pass

      try:
        kwargs['relay_state'] = saml_msg['RelayState']
      except KeyError:
        pass

      return self.do(saml_msg['SAMLRequest'], binding, **kwargs)
  
  def do(self, query, binding, relay_state='', encrypt_cert=None):
      pass
  