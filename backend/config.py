from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import importlib
import saml2.xmldsig as ds

class Settings(BaseSettings):
  host: str = Field(alias='APP_HOST', default='localhost')
  port: int = Field(alias='BACKEND_PORT', default=8000)
  use_https: bool = False
  query_string: str | None = None
  
  idp_config: str = './idp_conf.py'
  # valid: int
  # cert: str
  # id: str
  # keyfile: str
  # name: str
  # sign: str
  # mako_root: str = './'
  
  
  model_config = SettingsConfigDict(
    populate_by_name=True,
  )
  
# settings = Settings()

@lru_cache
def get_app_settings() -> Settings:
  settings = Settings()
  return settings

@lru_cache
def get_saml_settings():
  app_settings = get_app_settings()
  saml_settings = importlib.import_module(app_settings.idp_config)
  return saml_settings

def set_default_signature() -> None:
  idp_configs = get_saml_settings()
  sign_alg = None
  digest_alg = None
  try:
      sign_alg = idp_configs.SIGN_ALG
  except AttributeError:
      pass
    
  try:
      digest_alg = idp_configs.DIGEST_ALG
  except AttributeError:
      pass
    
  ds.DefaultSignature(sign_alg, digest_alg)