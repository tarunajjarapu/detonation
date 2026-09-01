FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py client.py /app/

RUN useradd --uid 10001 --create-home sandbox \
    && mkdir /trace-output \
    && chown sandbox:sandbox /trace-output
USER sandbox

CMD ["python3", "/app/client.py"]
