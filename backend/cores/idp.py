from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.sigver import encrypt_cert_from_item
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from fastapi import HTTPException
import logging
from config import get_app_settings
from server import IDP

logger = logging.getLogger('saml2.idp')

class IdPRequest:
  def __init__(self, user=None) -> None:
    self.settings = get_app_settings()
    self.user = user
    
  def redirect(self, query_json: dict):
    """Expects a HTTP-redirect request"""
    return self.operation(query_json, BINDING_HTTP_REDIRECT)

  def post(self, body_json: dict):
    """Expects a HTTP-POST request"""
    return self.operation(body_json, BINDING_HTTP_POST)

  def operation(self, saml_msg, binding):
    logger.debug('_operation: %s', saml_msg)
    is_request_included = (saml_msg and 'SAMLRequest' in saml_msg)
    if not is_request_included:
      return HTTPException(
        status_code=404,
        detail='Error parsing request or no request')
    else:
      kwargs, exception = self.__parse_signature(saml_msg)
      
      if exception is not None:
        return exception
      
      try:
        kwargs['encrypt_cert'] = encrypt_cert_from_item(saml_msg['req_info'].message)
      except KeyError:
        pass

      try:
        kwargs['relay_state'] = saml_msg['RelayState']
      except KeyError:
        pass

      return self.do(saml_msg['SAMLRequest'], binding, **kwargs)
  
  def __parse_signature(saml_msg: any) -> tuple[dict, HTTPException]:
    # saml_msg may also contain Signature and SigAlg
    if 'Signature' in saml_msg:
      try:
        return {
          'signature': saml_msg['Signature'],
          'sigalg': saml_msg['SigAlg'],
        }, None
      except KeyError:
        return None, HTTPException(
          status_code=404,
          detail='Signature Algorithm specification is missing')
    else:
      return {}, None
  
  def do(self, query, binding, relay_state='', encrypt_cert=None):
      pass
  
  def verify_request(self, query, binding):
    """
    :param query: The SAML query, transport encoded
    :param binding: Which binding the query came in over
    """
    resp_args = {}
    if not query:
      logger.info('Missing QUERY')
      return resp_args, HTTPException(401, 'Unknown user')

    if not self.req_info:
      self.req_info = IDP.parse_authn_request(query, binding)

    logger.info('parsed OK')
    _authn_req = self.req_info.message
    logger.debug("%s", _authn_req)

    self.__find_consumer_service(_authn_req)

    resp_args = {}
    try:
      resp_args = IDP.response_args(_authn_req)
      _resp = None
    except UnknownPrincipal as excp:
      _resp = IDP.create_error_response(_authn_req.id, self.destination, excp)
    except UnsupportedBinding as excp:
      _resp = IDP.create_error_response(_authn_req.id, self.destination, excp)

    return resp_args, _resp

  def __find_consumer_service(self, _authn_req):
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
  

  