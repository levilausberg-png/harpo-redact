# syntax=docker/dockerfile:1.7
# Harpo container image.
# CI builds it and runs tools/docker_smoke.py against it on every push and before every release (.github/workflows/
# ci.yml, job docker): compose up, health, sanitized requests, the live policy across a restart and a recreated
# container, logs without content, a clean shutdown.

# The base image, pinned by digest: python:3.12-slim-bookworm from the Docker official images (the multi-arch index).
# Dependabot keeps the digest current. To build from a mirror or a base image of your own instead:
#   docker build --build-arg PYTHON_IMAGE=registry.example.com/python:3.12-slim-bookworm .
ARG PYTHON_IMAGE=python-base
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS python-base

# ---------------------------------------------------------------- build stage
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Every dependency is pinned by version and SHA-256 (uv pip compile --generate-hashes).
COPY requirements.lock .
RUN pip install --require-hashes --no-deps -r requirements.lock

# spaCy English model (MIT), pinned by URL and checksum.
ARG SPACY_MODEL_URL=https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
ARG SPACY_MODEL_SHA256=1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85
ADD --checksum=sha256:${SPACY_MODEL_SHA256} ${SPACY_MODEL_URL} /build/en_core_web_sm-3.8.0-py3-none-any.whl
RUN pip install --no-deps /build/en_core_web_sm-3.8.0-py3-none-any.whl

# German NER and the multilingual fallback (both MIT), pinned the same way. Dutch (CC BY-SA 4.0), French (LGPL-LR) and
# Spanish (GPL-3.0) models are opt-in because of their licences: --build-arg EXTRA_NER_MODELS="nl fr es".
ARG SPACY_BASE=https://github.com/explosion/spacy-models/releases/download
ADD --checksum=sha256:fec69fec52b1780f2d269d5af7582a5e28028738bd3190532459aeb473bfa3e7 ${SPACY_BASE}/de_core_news_sm-3.8.0/de_core_news_sm-3.8.0-py3-none-any.whl /build/
ADD --checksum=sha256:6f3c4b853852ea9e9d2dc76cc950dddb10a7e4c42d813308caefe6c5e8be2f0a ${SPACY_BASE}/xx_ent_wiki_sm-3.8.0/xx_ent_wiki_sm-3.8.0-py3-none-any.whl /build/
RUN pip install --no-deps /build/de_core_news_sm-3.8.0-py3-none-any.whl /build/xx_ent_wiki_sm-3.8.0-py3-none-any.whl
ARG EXTRA_NER_MODELS=""
RUN for lang in $EXTRA_NER_MODELS; do \
      case "$lang" in \
        nl) m=nl_core_news_sm; h=a76978477821f213ca76a46c686df1b1d41462905d4868bc53eac086adca8b7e ;; \
        fr) m=fr_core_news_sm; h=7d6ad14cd5078e53147bfbf70fb9d433c6a3865b695fda2657140bbc59a27e29 ;; \
        es) m=es_core_news_sm; h=e451a83d6df79b87e9eed0cb553f03e99e36a3bab18a7b79f0dcfd1fdf875e12 ;; \
        *) echo "unknown language $lang" >&2; exit 1 ;; \
      esac; \
      python -c "import sys,urllib.request,hashlib; d=urllib.request.urlopen(sys.argv[1]).read(); assert hashlib.sha256(d).hexdigest()==sys.argv[2], 'checksum'; open(sys.argv[3],'wb').write(d)" \
        "${SPACY_BASE}/$m-3.8.0/$m-3.8.0-py3-none-any.whl" "$h" "/build/$m-3.8.0-py3-none-any.whl" && \
      pip install --no-deps "/build/$m-3.8.0-py3-none-any.whl"; \
    done

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-deps . && python -m compileall -q /opt/venv

# ---------------------------------------------------------------- runtime stage
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="Harpo" \
      org.opencontainers.image.description="A self-hosted privacy firewall for LLM calls: personal data and secrets become placeholders before a prompt leaves." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/levilausberg-png/harpo-redact"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HARPO_CONFIG=/etc/harpo/harpo.yaml
RUN groupadd --system --gid 10001 harpo \
 && useradd --system --uid 10001 --gid harpo --no-create-home --shell /usr/sbin/nologin harpo \
 && mkdir -p /var/lib/harpo && chown 10001:10001 /var/lib/harpo && chmod 700 /var/lib/harpo
COPY --from=build /opt/venv /opt/venv
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["harpo"]
CMD ["serve"]
