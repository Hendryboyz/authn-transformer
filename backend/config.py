from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
  host: str = Field(alias='APP_HOST', default='localhost')
  port: int = Field(alias='BACKEND_PORT', default=8000)
  
  model_config = SettingsConfigDict(
    populate_by_name=True,
  )
  
# settings = Settings()