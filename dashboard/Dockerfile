# Build from the REPO ROOT, not from dashboard/, e.g.:
#   docker build -f dashboard/Dockerfile -t cbad-dashboard .
# (docker-compose.yml in this directory already sets the context correctly)
FROM python:3.12-slim

# git is required by Stage 1's live feature collector (it shells out to `git`)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY dashboard/requirements.txt /app/dashboard/requirements.txt
RUN pip install --no-cache-dir -r /app/dashboard/requirements.txt

# Bring in the whole pipeline (stage1..stage9 + dashboard) so the dashboard's
# flat sibling-module imports and known artifact paths resolve correctly.
COPY . /app

WORKDIR /app/dashboard

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
