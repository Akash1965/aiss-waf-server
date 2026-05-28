#!/usr/bin/env bash
# Regenerate Go and Python gRPC stubs from aiss.proto
# Requirements:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#   pip install grpcio-tools

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p gen/go gen/python

echo "→ Generating Go stubs..."
protoc --go_out=gen/go --go_opt=paths=source_relative \
       --go-grpc_out=gen/go --go-grpc_opt=paths=source_relative \
       aiss.proto

echo "→ Generating Python stubs..."
python -m grpc_tools.protoc \
    -I. \
    --python_out=gen/python \
    --grpc_python_out=gen/python \
    aiss.proto

echo "Done."
