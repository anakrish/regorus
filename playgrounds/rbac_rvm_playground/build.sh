#!/bin/bash

# Build script for RBAC RVM Playground
# This script builds the WASM module and prepares the playground for deployment

set -e

echo "🔧 Building RBAC RVM Playground..."

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "📁 Script directory: $SCRIPT_DIR"
echo "📁 Repository root: $ROOT_DIR"

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack is not installed"
    echo "📦 Install it with: cargo install wasm-pack"
    exit 1
fi

echo "✅ wasm-pack found"

# Navigate to WASM bindings directory
cd "$ROOT_DIR/bindings/wasm"

echo "🔨 Building WASM module (this may take a minute)..."

# Build for web target
wasm-pack build --target web --out-dir "$SCRIPT_DIR/pkg"

if [ $? -eq 0 ]; then
    echo "✅ WASM module built successfully"
    echo "📦 Output in: $SCRIPT_DIR/pkg"
else
    echo "❌ WASM build failed"
    exit 1
fi

# Check the size of the WASM file
WASM_FILE="$SCRIPT_DIR/pkg/regorusjs_bg.wasm"
if [ -f "$WASM_FILE" ]; then
    SIZE=$(du -h "$WASM_FILE" | cut -f1)
    echo "📊 WASM file size: $SIZE"
fi

# Create .gitignore in pkg directory to not track generated files (optional)
cat > "$SCRIPT_DIR/pkg/.gitignore" << 'EOF'
# Generated WASM files
*.wasm
*.js
*.ts
*.txt
package.json
EOF

echo ""
echo "🎉 Build complete!"
echo ""
echo "Next steps:"
echo "1. Start a local server: python3 -m http.server 8000"
echo "2. Open http://localhost:8000 in your browser"
echo "3. Try the examples and compile policies!"
echo ""
echo "To deploy to GitHub Pages:"
echo "1. Commit the pkg directory"
echo "2. Push to your repository"
echo "3. Enable GitHub Pages in settings"
