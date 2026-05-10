#!/bin/bash

PRIVATE_KEY="k2XK5ZvU06iopt7xTGobruc9VM9ODJsjuWNij2v5w4Jn4xVsGiD7JXknnWe2BnVhHn190MKnnsXU/J8oNvppzw=="
PUBLIC_KEY="Z+MVbBog+yV5J51ntgZ1YR59fdDCp57F1PyfKDb6ac8="

# Inject Machine ID defaults to 0
export MACHINE_ID=${1:-0}
export PASETO_V4_PRIVATE_KEY=${2:-$PRIVATE_KEY}
export PASETO_V4_PUBLIC_KEY=${3:-$PUBLIC_KEY}

echo "Server starting with MACHINE_ID=$MACHINE_ID"

go run ./cmd/server