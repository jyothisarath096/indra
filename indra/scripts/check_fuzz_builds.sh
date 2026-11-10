#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo +nightly fuzz build
