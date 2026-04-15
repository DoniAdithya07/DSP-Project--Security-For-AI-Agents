const http = require("http");
const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const readArg = (name, fallback) => {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return fallback;
  return args[idx + 1];
};

const host = readArg("--host", "127.0.0.1");
const port = Number(readArg("--port", "4173"));
const rootDir = path.resolve(process.cwd(), readArg("--root", "dist"));

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".map": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

const resolvePath = (urlPath) => {
  const safePath = decodeURIComponent(urlPath.split("?")[0] || "/");
  const normalized = safePath === "/" ? "/index.html" : safePath;
  const candidate = path.resolve(rootDir, `.${normalized}`);
  if (!candidate.startsWith(rootDir)) {
    return path.join(rootDir, "index.html");
  }
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    return candidate;
  }
  return path.join(rootDir, "index.html");
};

const server = http.createServer((req, res) => {
  const filePath = resolvePath(req.url || "/");
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Server error");
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      "Content-Type": mimeTypes[ext] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    res.end(data);
  });
});

server.listen(port, host, () => {
  console.log(`Static test server running at http://${host}:${port} (root: ${rootDir})`);
});
