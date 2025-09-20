# Regorus Playground Deployment

<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

This document describes how to deploy the Regorus Playground to GitHub Pages.

## Overview

The playground is deployed to a separate repository (`anakrish/regorus-playground`) and served at:
**https://anakrish.github.io/regorus-playground/**

## Architecture

1. **Source**: The playground source code is in this repository (`regorus/docs/playground/`)
2. **Build**: WASM module is built from `bindings/wasm/`
3. **Deploy**: Built artifacts are pushed to `anakrish/regorus-playground` repository
4. **Serve**: GitHub Pages serves the playground from the deployment repository

## Setup Instructions

### 1. Create the Deployment Repository

```bash
# Create a new repository named 'regorus-playground'
gh repo create anakrish/regorus-playground --public --description "Interactive Regorus Playground"
```

### 2. Configure GitHub Secrets

Add the following secret to the source repository (`regorus`):

- **`PLAYGROUND_DEPLOY_TOKEN`**: Personal Access Token with `repo` scope to push to `anakrish/regorus-playground`

### 3. Enable GitHub Pages

In the `anakrish/regorus-playground` repository:
1. Go to Settings → Pages
2. Source: Deploy from a branch
3. Branch: `main`
4. Folder: `/ (root)`

## Manual Deployment

### Local Build

```bash
# Build the playground locally
./scripts/build-playground.sh

# The built playground will be in ./build-playground/
```

### Manual Push to Deployment Repository

```bash
# Clone the deployment repository
git clone https://github.com/anakrish/regorus-playground.git
cd regorus-playground

# Copy built files
cp -r ../regorus/build-playground/* .

# Commit and push
git add .
git commit -m "Manual deployment $(date)"
git push origin main
```

## Automatic Deployment

The GitHub Actions workflow (`.github/workflows/deploy-playground.yml`) automatically:

1. **Triggers** on:
   - Push to `playground` branch
   - Changes to playground files
   - Manual workflow dispatch

2. **Builds**:
   - Rust WASM module using `wasm-pack`
   - Copies artifacts to playground directory
   - Prepares deployment package

3. **Deploys**:
   - Pushes to `anakrish/regorus-playground` repository
   - Updates GitHub Pages automatically

## File Structure

```
regorus/
├── docs/playground/           # Playground source
│   ├── index.html
│   ├── playground.css
│   ├── playground-v2.js
│   └── pkg/                   # WASM artifacts (generated)
├── bindings/wasm/             # WASM source
├── scripts/build-playground.sh # Build script
└── .github/workflows/
    └── deploy-playground.yml   # Deployment workflow
```

## Deployment Repository Structure

```
regorus-playground/
├── index.html                 # Main playground page
├── playground.css             # Styles
├── playground-v2.js           # JavaScript
├── pkg/                       # WASM modules
│   ├── regorusjs.js
│   ├── regorusjs_bg.wasm
│   └── ...
├── .nojekyll                  # Ensure GitHub Pages serves all files
└── README.md                  # Auto-generated info
```

## Troubleshooting

### Build Failures
- Check Rust toolchain is installed
- Ensure `wasm-pack` is available
- Verify WASM build completes successfully

### Deployment Failures
- Verify `PLAYGROUND_DEPLOY_TOKEN` secret is set
- Check token has `repo` scope
- Ensure deployment repository exists

### Page Not Loading
- Check GitHub Pages is enabled
- Verify files are in deployment repository
- Check browser developer tools for errors

## URLs

- **Playground**: https://anakrish.github.io/regorus-playground/
- **Source Repository**: https://github.com/anakrish/regorus
- **Deployment Repository**: https://github.com/anakrish/regorus-playground
