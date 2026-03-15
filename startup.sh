#!/bin/bash
# Azure App Service startup command for Secure Zeph Gateway
export PYTHONPATH=/home/site/wwwroot
gunicorn apps.gateway.app.main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --timeout 120
