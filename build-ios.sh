#!/bin/bash

set -e

CRATE="indra-ffi"
LIB="libindra_ffi.a"

echo "Adding iOS targets..."
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add x86_64-apple-ios

echo "Building for physical device..."
cargo build -p $CRATE --release --target aarch64-apple-ios

echo "Building for simulator (Apple Silicon)..."
cargo build -p $CRATE --release --target aarch64-apple-ios-sim

echo "Building for simulator (Intel)..."
cargo build -p $CRATE --release --target x86_64-apple-ios

echo "Creating universal simulator library..."
mkdir -p target/universal-sim
lipo -create \
    target/aarch64-apple-ios-sim/release/$LIB \
    target/x86_64-apple-ios/release/$LIB \
    -output target/universal-sim/$LIB

echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/$LIB \
    -headers indra-ffi/include/ \
    -library target/universal-sim/$LIB \
    -headers indra-ffi/include/ \
    -output IndraFFI.xcframework

echo "Done: IndraFFI.xcframework"

# Write module maps so Swift can import the framework
MODULEMAP='framework module IndraFFI {
    umbrella header "indra.h"
    export *
    module * { export * }
}'

echo "$MODULEMAP" > IndraFFI.xcframework/ios-arm64/Headers/module.modulemap
echo "$MODULEMAP" > IndraFFI.xcframework/ios-arm64_x86_64-simulator/Headers/module.modulemap
echo "Module maps written"
