# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS semgrep

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --disable-pip-version-check --no-cache-dir --no-compile semgrep==1.184.0 \
    && /opt/semgrep/bin/pip uninstall --yes pip

FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=semgrep /opt/semgrep /opt/semgrep

ENV NODE_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    SRCAUDIT_CONTAINER=1 \
    SRCAUDIT_DATA_DIR=/var/lib/srcaudit \
    SECURITYSCANNER_SEMGREP_EXE=/opt/semgrep/bin/semgrep

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force \
    && install -d -o node -g node /var/lib/srcaudit

COPY ui.mjs scan.mjs LICENSE ./
COPY src/ ./src/
COPY web/ ./web/
COPY rules/ ./rules/
COPY data/ ./data/
COPY examples/ ./examples/

ENV HOME=/tmp
USER node
EXPOSE 8787
CMD ["node", "ui.mjs"]
