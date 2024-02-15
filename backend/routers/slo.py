from fastapi import APIRouter, Request

router = APIRouter(
  prefix='/slo',
  tags=['Single Logout']
)

@router.post('/post')
def logout_post(req: Request):
  return req.json()

@router.get('/redirect')
def logout_redirect(req: Request):
  return req.query_params
