from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from server import IDP
from hashlib import sha1
from idp import IdPRequest

class SingleSignOn(IdPRequest):
  def __init__(self, user=None) -> None:
    super().__init__(user)
    self.binding = ""
    self.response_bindings = None
    self.resp_args = {}
    self.binding_out = None
    self.destination = None
    self.req_info = None
    self.op_type = ""
  
  @staticmethod
  def _store_request(saml_msg):
      # logger.debug("_store_request: %s", saml_msg)
      key = sha1(saml_msg["SAMLRequest"].encode()).hexdigest()
      # store the AuthnRequest
      IDP.ticket[key] = saml_msg
      return key
      
  def post(self, body_json: dict):
    return self.operation(body_json, BINDING_HTTP_POST)
  
  def redirect(self, query_json: dict):
    try:
      key = query_json['key']
      saml_msg = IDP.ticket[key]
      self.req_info = saml_msg["req_info"]
      del IDP.ticket[key]
    except KeyError:
      pass
    else:
      return self.operation(query_json, BINDING_HTTP_REDIRECT)
  
  def do(self, query, binding, relay_state='', encrypt_cert=None):
    return super().do(query, binding, relay_state, encrypt_cert)