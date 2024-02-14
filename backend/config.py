from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
  host: str = Field(alias='APP_HOST', default='localhost')
  port: int = Field(alias='BACKEND_PORT', default=8000)
  use_https: bool = False
  query_string: str | None = None
  
  # idp_config: str = './idp_conf.py'
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
def get_settings() -> Settings:
  settings = Settings()
  return settings