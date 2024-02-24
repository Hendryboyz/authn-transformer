from fastapi import FastAPI
from config import get_app_settings
from routers import sso, slo
from cores.server import init_idp_server

settings = get_app_settings()
init_idp_server()
app = FastAPI()

app.include_router(sso.router)
app.include_router(slo.router)

@app.get('/')
def default():
  return {
    'greeting': 'hello FastAPI',
  }

@app.get('/health')
def health():
  return {
    'host': settings.host,
    'port': settings.port,
    'base': 'http://%s:%s' % (settings.host, settings.port),
  }