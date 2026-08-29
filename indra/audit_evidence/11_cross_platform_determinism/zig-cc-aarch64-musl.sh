#!/bin/sh
exec "$(dirname "$0")/rust-lld-driver.py" "$@"
