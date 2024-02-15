from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.sigver import encrypt_cert_from_item
from saml2.authn_context import INTERNETPROTOCOLPASSWORD, UNSPECIFIED
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from fastapi import HTTPException
import logging
from config import get_settings
from server import IDP

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
  
  def verify_request(self, query, binding):
        """
        :param query: The SAML query, transport encoded
        :param binding: Which binding the query came in over
        """
        resp_args = {}
        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized("Unknown user")
            return resp_args, resp(self.environ, self.start_response)

        if not self.req_info:
            self.req_info = IDP.parse_authn_request(query, binding)

        logger.info("parsed OK")
        _authn_req = self.req_info.message
        logger.debug("%s", _authn_req)

        try:
            self.binding_out, self.destination = IDP.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text,
                request=_authn_req,
            )
        except Exception as err:
            logger.error("Couldn't find receiver endpoint: %s", err)
            raise

        logger.debug("Binding: %s, destination: %s", self.binding_out, self.destination)

        resp_args = {}
        try:
            resp_args = IDP.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal as excp:
            _resp = IDP.create_error_response(_authn_req.id, self.destination, excp)
        except UnsupportedBinding as excp:
            _resp = IDP.create_error_response(_authn_req.id, self.destination, excp)

        return resp_args, _resp

  