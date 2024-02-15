from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.profile import ecp
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from server import IDP
from hashlib import sha1
from idp import IdPRequest

REPOZE_ID_EQUIVALENT = "uid"


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
  
  def do(self, query, binding_in, relay_state='', encrypt_cert=None, **kwargs):
    """
    :param query: The request
    :param binding_in: Which binding was used when receiving the query
    :param relay_state: The relay state provided by the SP
    :param encrypt_cert: Cert to use for encryption
    :return: A response
    """
    try:
        resp_args, _resp = self.verify_request(query, binding_in)
    except UnknownPrincipal as excp:
        logger.error("UnknownPrincipal: %s", excp)
        resp = ServiceError(f"UnknownPrincipal: {excp}")
        return resp(self.environ, self.start_response)
    except UnsupportedBinding as excp:
        logger.error("UnsupportedBinding: %s", excp)
        resp = ServiceError(f"UnsupportedBinding: {excp}")
        return resp(self.environ, self.start_response)

    if not _resp:
        identity = USERS[self.user].copy()
        # identity["eduPersonTargetedID"] = get_eptid(IDP, query, session)
        logger.info("Identity: %s", identity)

        if REPOZE_ID_EQUIVALENT:
            identity[REPOZE_ID_EQUIVALENT] = self.user
        try:
            try:
                metod = self.environ["idp.authn"]
            except KeyError:
                pass
            else:
                resp_args["authn"] = metod

            _resp = IDP.create_authn_response(
                identity, userid=self.user, encrypt_cert_assertion=encrypt_cert, **resp_args
            )
        except Exception as excp:
            logging.error(exception_trace(excp))
            resp = ServiceError(f"Exception: {excp}")
            return resp(self.environ, self.start_response)

    logger.info("AuthNResponse: %s", _resp)
    if self.op_type == "ecp":
        kwargs = {"soap_headers": [ecp.Response(assertion_consumer_service_url=self.destination)]}
    else:
        kwargs = {}

    http_args = IDP.apply_binding(
        self.binding_out, f"{_resp}", self.destination, relay_state, response=True, **kwargs
    )

    logger.debug("HTTPargs: %s", http_args)
    return self.response(self.binding_out, http_args)