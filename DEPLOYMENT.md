# Deploy RVM Playground to Separate Repository

This directory contains the RVM Playground that should be deployed to:
**https://github.com/anakrish/rego-virtual-machine-playground**

## Deployment Instructions

### 1. Create the Separate Repository

1. Create a new repository: `rego-virtual-machine-playground`
2. Initialize it as a public repository
3. Enable GitHub Pages in repository settings

### 2. Copy Files to Separate Repository

Copy the following files from `rvm-playground/` to the root of the new repository:

```bash
# Copy all playground files
cp -r rvm-playground/* /path/to/rego-virtual-machine-playground/

# Copy WASM bindings source (for building)
mkdir -p /path/to/rego-virtual-machine-playground/wasm-src
cp -r bindings/wasm/* /path/to/rego-virtual-machine-playground/wasm-src/
cp -r src /path/to/rego-virtual-machine-playground/regorus-src/
cp Cargo.toml /path/to/rego-virtual-machine-playground/
```

### 3. GitHub Actions Workflow

The separate repository should include this GitHub Actions workflow in `.github/workflows/deploy.yml`:

```yaml
name: Build and Deploy RVM Playground

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: "pages"
  cancel-in-progress: false

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32-unknown-unknown
          override: true
          
      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
        
      - name: Build WASM module
        run: |
          cd wasm-src
          wasm-pack build --target web --out-dir ../wasm
          
      - name: Setup Pages
        uses: actions/configure-pages@v4
        
      - name: Update app.js for production
        run: |
          # Enable real WASM loading
          sed -i 's|// import init|import init|g' app.js
          sed -i 's|// await init()|await init()|g' app.js
          
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: '.'
          
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
        if: github.ref == 'refs/heads/main'
```

### 4. Repository Structure

The separate repository should have this structure:

```
rego-virtual-machine-playground/
├── .github/
│   └── workflows/
│       └── deploy.yml
├── wasm-src/           # Source for WASM module
│   ├── src/
│   ├── Cargo.toml
│   └── build.rs
├── regorus-src/        # Regorus source code
│   └── ...
├── wasm/              # Generated WASM files (gitignored)
├── index.html         # Main playground HTML
├── style.css          # Playground styles
├── app.js             # Playground JavaScript
├── README.md          # Playground documentation
├── .nojekyll          # Bypass Jekyll
└── .gitignore         # Ignore generated files
```

### 5. Configuration Updates

Update the following files for the separate repository:

#### `app.js` - Enable WASM Loading
```javascript
// Uncomment these lines for production:
import init, { Engine, RegoVM, generateAssemblyListing, AssemblyConfig } from './wasm/regorusjs.js';

async loadWASM() {
    await init();
    this.wasmModule = { Engine, RegoVM, generateAssemblyListing, AssemblyConfig };
    this.updateVMStatus('WASM Loaded');
}
```

#### `README.md` - Update URLs
- Change repository URLs to point to the new repository
- Update GitHub Pages URL to the new domain

### 6. .gitignore for Separate Repository

```
# Generated WASM files
/wasm/
*.wasm
*.js.map

# Build artifacts
target/
Cargo.lock

# Editor files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Logs
*.log
```

### 7. Enable GitHub Pages

In the separate repository settings:
1. Go to Settings → Pages
2. Set Source to "GitHub Actions"
3. The playground will be available at: `https://anakrish.github.io/rego-virtual-machine-playground/`

## Benefits of Separate Repository

1. **Clean URLs**: Shorter, more memorable URL
2. **Independent Versioning**: Playground can have its own release cycle
3. **Focused Issues**: Issues and discussions specific to the playground
4. **Better SEO**: Dedicated repository for discoverability
5. **Simplified CI/CD**: Deployment focused only on the playground