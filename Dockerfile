FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir paramiko requests

COPY honeypot.py /app/
COPY entrypoint.sh /app/

RUN mkdir -p /app/keys /app/logs && \
    chmod +x /app/entrypoint.sh

EXPOSE 2222

ENTRYPOINT ["/app/entrypoint.sh"]
