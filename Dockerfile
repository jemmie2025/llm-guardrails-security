FROM python:3.12-slim-trixie AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefer-binary -r requirements.txt

RUN set -eu; \
    mkdir -p /opt/runtime-libs; \
    for lib in \
      libbz2.so.1.0 \
      liblzma.so.5 \
      libsqlite3.so.0 \
      libffi.so.8 \
      libexpat.so.1 \
      libuuid.so.1 \
      libgomp.so.1 \
      libreadline.so.8 \
      libncursesw.so.6 \
      libtinfo.so.6 \
      libcrypt.so.1; do \
      if [ -e "/usr/lib/x86_64-linux-gnu/$lib" ]; then \
        cp -L "/usr/lib/x86_64-linux-gnu/$lib" /opt/runtime-libs/; \
      fi; \
    done

FROM gcr.io/distroless/cc-debian13:nonroot

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu

WORKDIR /app

COPY --from=builder /usr/local/ /usr/local/
COPY --from=builder /opt/runtime-libs/ /usr/lib/x86_64-linux-gnu/

COPY --chown=65532:65532 app/ ./app/
COPY --chown=65532:65532 guardrails/ ./guardrails/

USER 65532:65532

EXPOSE 8000

CMD ["/usr/local/bin/python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
