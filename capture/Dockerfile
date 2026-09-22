# Wireshark's dissection engine plus the extraction service.
#
# tshark is the reason this image exists: it brings the full dissector table and
# TCP reassembly, which is what lets a payload split across many frames arrive at
# the analysis stage as a single application message.

FROM python:3.12-slim-bookworm

# The tshark package prompts about allowing non-root capture. Answering ahead of
# the install keeps the build non-interactive and lets the service run unprivileged.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        tshark \
        tcpdump \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The extractor only reads capture files; it never opens a live interface, so it
# needs no capabilities and runs as an ordinary user.
RUN useradd --system --create-home --shell /usr/sbin/nologin extractor

WORKDIR /app

COPY --chown=extractor:extractor analysis/pyproject.toml ./
COPY --chown=extractor:extractor analysis/deception_shield ./deception_shield

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir boto3 \
    && pip install --no-cache-dir --no-deps -e .

USER extractor

ENV CAPTURE_DIR=/pcap \
    OUTPUT_DIR=/extracted \
    LOGSTASH_HOST=logstash \
    LOGSTASH_PORT=5400 \
    POLL_INTERVAL=60 \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import pathlib,os,sys; sys.exit(0 if pathlib.Path(os.environ['CAPTURE_DIR']).is_dir() else 1)"

ENTRYPOINT ["python", "-m", "deception_shield.extractor"]
