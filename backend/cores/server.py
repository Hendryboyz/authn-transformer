from saml2 import server
from config import get_app_settings

class Cache:
  def __init__(self):
    self.user2uid = {}
    self.uid2user = {}

IDP: server.Server = None

def init_idp_server():
  app_settings = get_app_settings()
  IDP = server.Server(app_settings.idp_config, cache=Cache())
  IDP.ticket = {}
  return IDP
