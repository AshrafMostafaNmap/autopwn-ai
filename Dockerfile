# AutoPwn AI — self-contained purple-team agent image.
#
# Bundles the Python engine plus the curated, non-destructive recon/detection
# toolset so `docker run autopwn ...` works on a fresh machine with no host deps.
# The scanners are fetched by AutoPwn's own installer (official GitHub releases,
# SHA-256 verified) — the same path `autopwnai tools install` uses on a laptop.

FROM python:3.12-slim-bookworm

# System scanners + DNS/TLS tools + WeasyPrint (PDF) native libraries.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan dnsutils openssl curl ca-certificates \
      libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
      libffi8 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY autopwn ./autopwn
RUN pip install --no-cache-dir . && \
    AUTOPWN_HOME=/tmp/autopwn autopwnai tools install && \
    mv /tmp/autopwn/data/bin/* /usr/local/bin/ && rm -rf /tmp/autopwn

# Non-root by default — least privilege.
RUN useradd -m -u 10001 autopwn && \
    mkdir -p /engagements && chown autopwn:autopwn /engagements
USER autopwn
RUN nuclei -update-templates -silent -disable-update-check || true
ENV AUTOPWN_RUN_ROOT=/engagements/runs \
    AUTOPWN_HOME=/engagements/.autopwn
WORKDIR /engagements

# Interactive app (settings + encrypted keys persist in the mounted volume):
#   docker run -it --rm -v "$PWD/engagements:/engagements" autopwn
# One-shot:
#   docker run --rm -e ANTHROPIC_API_KEY=... -v "$PWD/engagements:/engagements" autopwn \
#       run "assess juice.company.lab for injection" -t juice.company.lab --authorize
# (no TTY and no subcommand → prints help)
ENTRYPOINT ["autopwnai"]
