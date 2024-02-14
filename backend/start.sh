#!/bin/bash
export APP_HOST=sso.craftsmanhenry.xyz
export BACKEND_PORT=8000

## Run `pipenv shell` first
uvicorn main:app --port "$BACKEND_PORT" --reload 