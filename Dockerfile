# ─── Stage 1: Build ────────────────────────────────────────────────────────
# go-duckdb requires CGO (embeds DuckDB C++ engine).
# Use Debian Bookworm (glibc) — DuckDB is not musl/Alpine compatible.
FROM golang:1.22-bookworm AS builder

# Build args to control optional native backends:
#   --build-arg ENABLE_HYPERSCAN=1   → Intel Hyperscan (-tags hyperscan)  *** x86_64 ONLY ***
#   --build-arg ENABLE_ONNX=1        → ONNX Runtime     (-tags onnx)
# Both default to 0 (safe on arm64 / Apple Silicon).
ARG ENABLE_HYPERSCAN=0
ARG ENABLE_ONNX=0
ARG ONNX_VERSION=1.18.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc g++ build-essential curl ca-certificates pkg-config \
    && if [ "$ENABLE_HYPERSCAN" = "1" ]; then apt-get install -y --no-install-recommends libhyperscan-dev; fi \
    && rm -rf /var/lib/apt/lists/*

# Download and install ONNX Runtime shared library (needed when ENABLE_ONNX=1)
RUN if [ "$ENABLE_ONNX" = "1" ]; then \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ORT_ARCH="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then ORT_ARCH="aarch64"; \
    else ORT_ARCH="x64"; fi && \
    curl -fsSL -o /tmp/onnxruntime.tgz \
        "https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/onnxruntime-linux-${ORT_ARCH}-${ONNX_VERSION}.tgz" && \
    tar -xzf /tmp/onnxruntime.tgz -C /tmp && \
    cp -r /tmp/onnxruntime-linux-${ORT_ARCH}-${ONNX_VERSION}/lib/* /usr/local/lib/ && \
    cp -r /tmp/onnxruntime-linux-${ORT_ARCH}-${ONNX_VERSION}/include/* /usr/local/include/ && \
    ldconfig && \
    rm -rf /tmp/onnxruntime* ; \
    else \
    # Placeholder so the COPY glob always matches in the runtime stage
    touch /usr/local/lib/libonnxruntime_disabled ; \
    fi

WORKDIR /build

COPY go.mod ./
COPY . .

# Accumulate build tags from enabled backends, then compile
RUN BUILD_TAGS="" && \
    [ "$ENABLE_HYPERSCAN" = "1" ] && BUILD_TAGS="${BUILD_TAGS:+$BUILD_TAGS,}hyperscan" || true && \
    [ "$ENABLE_ONNX" = "1" ]      && BUILD_TAGS="${BUILD_TAGS:+$BUILD_TAGS,}onnx"      || true && \
    echo "Building with tags: ${BUILD_TAGS:-none}" && \
    go mod tidy && go mod download && \
    if [ -n "$BUILD_TAGS" ]; then \
        CGO_ENABLED=1 go test -v -count=1 -tags "$BUILD_TAGS" ./... 2>&1 | tee /build/test-results.txt && \
        CGO_ENABLED=1 GOOS=linux go build -tags "$BUILD_TAGS" \
            -ldflags="-s -w" -o /build/aiss-agent ./cmd/agent ; \
    else \
        CGO_ENABLED=1 go test -v -count=1 ./... 2>&1 | tee /build/test-results.txt && \
        CGO_ENABLED=1 GOOS=linux go build \
            -ldflags="-s -w" -o /build/aiss-agent ./cmd/agent ; \
    fi

# ─── Stage 2: Runtime ───────────────────────────────────────────────────────
FROM debian:bookworm-slim

ARG ENABLE_HYPERSCAN=0
ARG ENABLE_ONNX=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata \
    && if [ "$ENABLE_HYPERSCAN" = "1" ]; then apt-get install -y --no-install-recommends libhyperscan5; fi \
    && rm -rf /var/lib/apt/lists/*

# Copy ONNX Runtime shared library from builder (placeholder file exists when disabled)
COPY --from=builder /usr/local/lib/libonnxruntime* /usr/local/lib/
RUN ldconfig

WORKDIR /app

COPY --from=builder /build/aiss-agent       /app/aiss-agent
COPY --from=builder /build/test-results.txt /app/test-results.txt
COPY rules/ /app/rules/

RUN mkdir -p /var/lib/aiss /etc/aiss /etc/aiss/ml /tmp

RUN cat > /etc/aiss/aiss.conf << 'EOF'
agent_id = ""
server_url = "http://aiss-server:8080"
socket_path = "/tmp/aiss.sock"
db_path = "/var/lib/aiss/aiss.db"
log_level = "info"
mode = "enforce"
ml_block_threshold = 0.85
verdict_cache_ttl = 60
rules_dir = "/app/rules/yara"
patterns_file = "/app/rules/hyperscan/cve_patterns.json"
onnx_model = "/etc/aiss/ml/aiss_model.onnx"
socket_timeout_ms = 500
max_workers = 256
EOF

EXPOSE 8090

ENTRYPOINT ["/app/aiss-agent"]
CMD ["--config", "/etc/aiss/aiss.conf"]
