FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    openconnect iproute2 iptables ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# Pin both version and checksum. This release targets Windows/Linux amd64.
RUN curl -fsSL https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz -o /tmp/sing-box.tar.gz \
    && echo 'e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee  /tmp/sing-box.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/sing-box.tar.gz -C /tmp \
    && cp /tmp/sing-box-1.14.3-linux-amd64/sing-box /usr/local/bin/sing-box \
    && rm -rf /tmp/sing-box*
WORKDIR /app
COPY vpnctl.py vpnc-script.py ./
COPY static ./static
RUN chmod +x /app/vpnc-script.py
ENV VPN_DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/app/vpnctl.py"]
