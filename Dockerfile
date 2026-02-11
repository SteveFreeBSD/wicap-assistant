FROM docker:27-cli AS dockercli

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Runtime tools:
# - git: git metadata and history windows
# - iproute2: `ss -ltnp` probe
RUN apt-get update \
    && apt-get install -y --no-install-recommends git iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI + compose plugin from official docker cli image
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker /usr/local/libexec/docker

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN python -m pip install --no-cache-dir .

ENTRYPOINT ["wicap-assist"]
CMD ["--help"]
