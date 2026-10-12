# ── Stage 1: builder ────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: runtime (distroless, non-root) ─────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot
LABEL maintainer="Apisit Suansane"
WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /root/.local /home/nonroot/.local
ENV PATH=/home/nonroot/.local/bin:$PATH
ENV PYTHONPATH=/home/nonroot/.local/lib/python3.12/site-packages
ENV PORT=8001

# Copy source code with non-root ownership
COPY --chown=nonroot:nonroot app/ /app/

EXPOSE 8001
USER nonroot

ENTRYPOINT ["python", "-m", "app.main"]