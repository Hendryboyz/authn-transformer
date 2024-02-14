from fastapi import APIRouter, Request

router = APIRouter(
  prefix='/sso',
  tags=['Single Sign-on']
)

@router.post('/post')
def authn_post(req: Request):
  return req.json()

@router.get('/redirect')
def authn_redirect(req: Request):
  return req.query_params
