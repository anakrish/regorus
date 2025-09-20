#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Build script for Regorus Playground deployment
# This script builds the WASM module and prepares the playground for GitHub Pages

set -e

echo "🚀 Building Regorus Playground..."

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "📁 Root directory: $ROOT_DIR"

# Change to the WASM binding directory
cd "$ROOT_DIR/bindings/wasm"

echo "🔧 Building WASM module with wasm-pack..."
# Build the WASM module for web target
wasm-pack build --target web --out-dir pkg

if [ $? -ne 0 ]; then
    echo "❌ WASM build failed!"
    exit 1
fi

echo "✅ WASM build completed successfully"

# Copy WASM artifacts to playground directory
echo "📋 Copying WASM artifacts to playground..."
cp -r pkg "$ROOT_DIR/docs/playground/"

echo "📝 Creating deployment directory structure..."
# Create a temporary build directory
BUILD_DIR="$ROOT_DIR/build-playground"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy playground files to build directory
cp -r "$ROOT_DIR/docs/playground/"* "$BUILD_DIR/"

# Create index.html at root level for GitHub Pages
cp "$BUILD_DIR/index.html" "$BUILD_DIR/index.html.bak"

echo "🌐 Playground built successfully!"
echo "📂 Build output: $BUILD_DIR"
echo "🚀 Ready for deployment to GitHub Pages"
echo ""
echo "To deploy:"
echo "1. Push the contents of '$BUILD_DIR' to the 'regorus-playground' repository"
echo "2. Enable GitHub Pages for that repository"
echo "3. Access at: https://anakrish.github.io/regorus-playground/"

echo ""
echo "✨ Build complete!"