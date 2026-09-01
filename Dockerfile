FROM node:24-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 strace \
    && rm -rf /var/lib/apt/lists/*

# A pinned, genuine MCP reference server rather than our test implementation.
RUN npm install --global @modelcontextprotocol/server-filesystem@2026.7.10

WORKDIR /app
COPY client.py adversarial_server.py /app/
RUN mkdir /sandbox-data \
    && printf 'hello from a real MCP server\n' > /sandbox-data/hello.txt

RUN useradd --uid 10001 --create-home sandbox \
    && mkdir /trace-output \
    && chown sandbox:sandbox /trace-output
USER sandbox

CMD ["strace", "-f", "-ttt", "-yy", "-s", "512", "-e", "trace=%file,%process,%network,read,write", "-o", "/trace-output/mcp.strace", "mcp-server-filesystem", "/sandbox-data"]
