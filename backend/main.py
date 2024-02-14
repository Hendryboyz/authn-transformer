from fastapi import Depends, FastAPI
import logging
from functools import lru_cache
from typing import Annotated
from config import Settings

@lru_cache
def get_settings():
  logging.info('init and loading settings')
  return Settings()

app = FastAPI()

@app.get('/')
def default():
  return {
    'greeting': 'hello FastAPI',
  }

@app.get('/health')
def health(settings: Annotated[Settings, Depends(get_settings)]):
  return {
    'host': settings.host,
    'port': settings.port,
  }