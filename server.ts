import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/dashboard') {
    const htmlPath = path.resolve(__dirname, 'dashboard.html');
    console.log(`[server] Serving file from: ${htmlPath}`);
    fs.readFile(htmlPath, 'utf8', (err, data) => {
      if (err) {
        console.error('[server] File read error:', err);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Internal Server Error: ${err.message}`);
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data);
      }
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
});

// Loopback-only (127.0.0.1): Aukora FU is a LOCAL Fusion observer. Never all-interfaces — it has no signed
// or authenticated network lane. It serves a static advisory-evidence visualization; it grants no authority.
server.listen(9900, '127.0.0.1', () => {
  console.log('Aukora-Fu Fusion observer running at: http://127.0.0.1:9900 (local, observer-only, no authority)');
});
