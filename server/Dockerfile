FROM python:3.12-slim

WORKDIR /app

# System deps:
#   gcc / g++ / libssl-dev  → grpcio compiles a C extension at install time
#   curl                    → health probe + Doris Stream Load
#   default-libmysqlclient-dev (optional) — only if using mysqlclient instead of pymysql
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY proto/ ./proto/

# ── Compile gRPC proto stubs ──────────────────────────────────────────────
# Generates aiss_pb2.py and aiss_pb2_grpc.py into /app/ so they can be
# imported by grpc_server.py.  Requires grpcio-tools (in requirements.txt).
RUN python -m grpc_tools.protoc \
        --proto_path=proto \
        --python_out=app \
        --grpc_python_out=app \
        proto/aiss.proto && \
    echo "gRPC stubs generated successfully"

# Persistent DuckDB data directory + ONNX model mount point
RUN mkdir -p /data /etc/aiss/ml

# Health probe — uses ${PORT:-8080} so it works on Render (PORT injected)
# and locally (falls back to 8080).  Shell form is required for env expansion.
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:${PORT:-8080}/health || exit 1

ENV AISS_ENVIRONMENT=production \
    AISS_HOST=0.0.0.0 \
    AISS_PORT=8080 \
    AISS_DATABASE_URL=duckdb:////data/aiss.duckdb \
    AISS_GRPC_PORT=50051

EXPOSE 8080
EXPOSE 50051

# Single worker required: DuckDB allows only one write process per file.
# Shell form (not JSON array) so ${PORT:-8080} is expanded at runtime.
# Render injects $PORT; local Docker falls back to 8080.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --loop uvloop --access-log
