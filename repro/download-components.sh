#!/bin/bash

: "${DRIVER_TOOLS:?Set DRIVER_TOOLS to a check-out of mongodb-labs/drivers-evergreentools}"

mkdir -p "$HOME"/mongodl/crypt_shared
uv run "$DRIVER_TOOLS"/.evergreen/mongodl.py --component crypt_shared --version 7.0.25 --out "$HOME"/mongodl/crypt_shared/7.0.25
uv run "$DRIVER_TOOLS"/.evergreen/mongodl.py --component crypt_shared --version 8.0.15 --out "$HOME"/mongodl/crypt_shared/8.0.15
