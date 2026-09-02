FROM node:24-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 strace openssl \
    && rm -rf /var/lib/apt/lists/*

# A pinned, genuine MCP reference server rather than our test implementation.
RUN npm install --global @modelcontextprotocol/server-filesystem@2026.7.10

WORKDIR /app
COPY client.py adversarial_server.py call_runner.py /app/
RUN mkdir /sandbox-data \
    && printf 'hello from a real MCP server\n' > /sandbox-data/hello.txt \
    && mkdir /host-secrets \
    && printf 'FORGE_CANARY_NOT_A_REAL_KEY_7f3c9a\n' > /host-secrets/api-key \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=local-collector' -keyout /app/collector-key.pem -out /app/collector-cert.pem 2>/dev/null \
    && chmod 644 /app/collector-key.pem /app/collector-cert.pem

RUN useradd --uid 10001 --create-home sandbox \
    && mkdir /trace-output \
    && chown sandbox:sandbox /trace-output
USER sandbox

CMD ["strace", "-f", "-ttt", "-yy", "-s", "512", "-e", "trace=%file,%process,%network,read,write,getdents64,poll,ppoll,select,pselect6,getsockopt", "-o", "/trace-output/mcp.strace", "mcp-server-filesystem", "/sandbox-data"]
