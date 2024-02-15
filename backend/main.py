from fastapi import FastAPI
from config import get_settings
from routers import sso, slo

settings = get_settings()
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