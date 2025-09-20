# Regorus Playground Setup Guide

<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

## Quick Start for Deployment

### Prerequisites
1. Create the deployment repository: `anakrish/regorus-playground`
2. Generate a Personal Access Token with `repo` scope
3. Add the token as `PLAYGROUND_DEPLOY_TOKEN` secret in this repository

### Manual Deployment Steps

```bash
# 1. Build the playground
./scripts/build-playground.sh

# 2. Clone the deployment repository  
git clone https://github.com/anakrish/regorus-playground.git
cd regorus-playground

# 3. Copy built files
cp -r ../regorus/build-playground/* .

# 4. Commit and push
git add .
git commit -m "Deploy playground $(date)"
git push origin main
```

### Automated Deployment

Push to the `playground` branch to trigger automatic deployment via GitHub Actions.

The playground will be available at: **https://anakrish.github.io/regorus-playground/**

## Repository Setup Commands

```bash
# Create the deployment repository
gh repo create anakrish/regorus-playground --public --description "Interactive Regorus Playground"

# Add deployment token secret (replace TOKEN with actual token)
gh secret set PLAYGROUND_DEPLOY_TOKEN --body "TOKEN" --repo anakrish/regorus

# Enable GitHub Pages for deployment repository
# (This needs to be done manually in GitHub UI: Settings → Pages → Source: Deploy from branch → main)
```

## File Structure

```
build-playground/
├── index.html              # Main playground interface
├── playground.css          # Styling
├── playground-v2.js        # JavaScript logic
├── pkg/                    # WASM artifacts
│   ├── regorusjs.js
│   ├── regorusjs_bg.wasm
│   └── ...
└── .nojekyll              # GitHub Pages config
```

## Troubleshooting

- **Build fails**: Ensure Rust and wasm-pack are installed
- **Deployment fails**: Check that `PLAYGROUND_DEPLOY_TOKEN` secret is set
- **Page not loading**: Verify GitHub Pages is enabled for deployment repository
- **WASM errors**: Check browser console for loading issues

## Development

For local development:

```bash
# Build WASM module
cd bindings/wasm
wasm-pack build --target web

# Copy to playground
cp -r pkg ../../../docs/playground/

# Serve locally
cd ../../docs
python3 -m http.server 8080
# Visit: http://localhost:8080/playground/
```