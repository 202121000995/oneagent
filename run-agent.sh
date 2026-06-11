#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
exec /Users/apple/Library/Go/sdk/go1.26.3/bin/go run ./cmd
