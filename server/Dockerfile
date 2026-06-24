# Build from the REPO ROOT, e.g.:
#   docker build -f server/Dockerfile -t cbad-api .
# (the root docker-compose.yml already sets the context correctly)
FROM python:3.11-slim

# git is required by Stage 1's live feature collector (it shells out to `git`)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt

# Bring in the whole pipeline (stage1..stage9 + dashboard/core + server) so
# server/bootstrap.py's sys.path insertion and the stage engines' own
# artifact paths resolve correctly.
COPY . /app

WORKDIR /app/server

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
