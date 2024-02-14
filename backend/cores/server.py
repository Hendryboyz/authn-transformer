from saml2 import server
from config import get_settings

class Cache:
  def __init__(self):
    self.user2uid = {}
    self.uid2user = {}

IDP: server.Server = None

def init_idp_server():
  IDP = server.Server('./idp_conf.py', cache=Cache())
  IDP.ticket = {}
