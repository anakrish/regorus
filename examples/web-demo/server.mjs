// Simple HTTP server with COOP/COEP headers for SharedArrayBuffer support.
// Required by z3-solver WASM which uses threads via SharedArrayBuffer.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8080;

const MIME_TYPES = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.mjs':  'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.rego': 'text/plain',
  '.cedar':'text/plain',
  '.smt2': 'text/plain',
};

// Directories to search for files (in order)
const SEARCH_DIRS = [
  __dirname,                                          // web-demo/
  path.join(__dirname, '../../bindings/wasm/pkg'),    // wasm-pack output
  path.join(__dirname, 'node_modules/z3-solver/build'), // z3-solver WASM files
];

function resolveFile(urlPath) {
  // Normalize URL path
  let filePath = urlPath === '/' ? '/index.html' : urlPath;

  // z3-solver paths: /z3-solver/build/... → node_modules/z3-solver/build/...
  if (filePath.startsWith('/z3-solver/')) {
    const resolved = path.join(__dirname, 'node_modules', filePath.substring(1));
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) return resolved;
  }

  // node_modules paths
  if (filePath.startsWith('/node_modules/')) {
    const resolved = path.join(__dirname, filePath.substring(1));
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) return resolved;
  }

  for (const dir of SEARCH_DIRS) {
    const fullPath = path.join(dir, filePath);
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      return fullPath;
    }
  }
  return null;
}

const server = http.createServer((req, res) => {
  const filePath = resolveFile(req.url);

  if (!filePath) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
    return;
  }

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  // COOP/COEP headers — required for SharedArrayBuffer
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  // Disable caching during development
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  const data = fs.readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': contentType });
  res.end(data);
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log('Press Ctrl+C to stop.');
});
