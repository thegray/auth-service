#!/bin/bash

PRIVATE_KEY="private_1"
PUBLIC_KEY="public_1"

# Inject Machine ID defaults to 0
export MACHINE_ID=${1:-0}
export PASETO_V4_PRIVATE_KEY=${2:-$PRIVATE_KEY}
export PASETO_V4_PUBLIC_KEY=${3:-$PUBLIC_KEY}

echo "Server starting with MACHINE_ID=$MACHINE_ID"

go run ./cmd/server