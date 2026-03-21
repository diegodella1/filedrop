const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');
const crypto = require('crypto');
const archiver = require('archiver');

const app = express();
const router = express.Router();
const PORT = 3456;
const BASE_DIR = '/home/diego/Documents';
const SELF_DIR = path.join(BASE_DIR, 'filedrop');

// --- Auth ---

const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  console.error('ADMIN_SECRET env var is required');
  process.exit(1);
}

const TOKEN_HASH = crypto.createHash('sha256').update(ADMIN_SECRET).digest('hex');

function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie;
  if (!header) return cookies;
  header.split(';').forEach(c => {
    const [key, ...val] = c.split('=');
    cookies[key.trim()] = val.join('=').trim();
  });
  return cookies;
}

function isAuthenticated(req) {
  const cookie = parseCookies(req)['filedrop_auth'];
  if (!cookie || cookie.length !== TOKEN_HASH.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(TOKEN_HASH));
}

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FileDrop — Login</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-xl shadow-sm border p-8 w-80">
    <div class="flex items-center gap-2 mb-6">
      <svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
      <h1 class="text-xl font-bold text-gray-800">FileDrop</h1>
    </div>
    <form id="loginForm">
      <input id="secret" type="password" placeholder="Admin secret" autocomplete="current-password"
        class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 mb-4">
      <p id="error" class="text-red-500 text-sm mb-3 hidden">Invalid secret</p>
      <button type="submit" class="w-full bg-blue-500 hover:bg-blue-600 text-white text-sm py-2 rounded-lg transition font-medium">Log in</button>
    </form>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const secret = document.getElementById('secret').value;
      const res = await fetch(location.pathname.replace(/\\/+$/, '') + '/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret })
      });
      if (res.ok) {
        location.reload();
      } else {
        document.getElementById('error').classList.remove('hidden');
      }
    });
  </script>
</body>
</html>`;

app.use(express.json());

// Login endpoint — before auth middleware
app.post('/api/login', (req, res) => {
  const { secret } = req.body || {};
  if (!secret || secret.length !== ADMIN_SECRET.length ||
      !crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(ADMIN_SECRET))) {
    return res.status(401).json({ error: 'Invalid secret' });
  }
  res.setHeader('Set-Cookie',
    `filedrop_auth=${TOKEN_HASH}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${30 * 24 * 3600}`);
  res.json({ ok: true });
});

// Logout endpoint
app.post('/api/logout', (_req, res) => {
  res.setHeader('Set-Cookie', 'filedrop_auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  res.json({ ok: true });
});

// Auth middleware — block everything else if not authenticated
app.use((req, res, next) => {
  if (isAuthenticated(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.send(LOGIN_HTML);
});

// --- Path safety ---

function safePath(requestedPath) {
  const relative = requestedPath || '';
  const resolved = path.resolve(BASE_DIR, relative);
  if (!resolved.startsWith(BASE_DIR + path.sep) && resolved !== BASE_DIR) {
    return null;
  }
  // Block access to the filedrop directory itself
  if (resolved === SELF_DIR || resolved.startsWith(SELF_DIR + path.sep)) {
    return null;
  }
  return resolved;
}

// --- Multer setup ---

const storage = multer.diskStorage({
  destination: (req, _file, cb) => {
    const dest = safePath(req.query.path);
    if (!dest) return cb(new Error('Invalid path'));
    cb(null, dest);
  },
  filename: (_req, file, cb) => {
    // Preserve original filename, decode URI-encoded names
    cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
  }
});
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 * 1024 } }); // 2 GB limit

// --- Static files ---

router.use(express.static(path.join(__dirname, 'public')));

// --- API: List files ---

router.get('/api/files', async (req, res) => {
  const dir = safePath(req.query.path);
  if (!dir) return res.status(400).json({ error: 'Invalid path' });

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const items = [];
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      // Skip the filedrop directory when listing BASE_DIR
      if (fullPath === SELF_DIR) continue;
      try {
        const stat = await fs.stat(fullPath);
        items.push({
          name: entry.name,
          isDirectory: entry.isDirectory(),
          size: stat.size,
          modified: stat.mtime,
        });
      } catch {
        // Skip entries we can't stat (broken symlinks, etc)
      }
    }
    // Sort: directories first, then alphabetical
    items.sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    res.json(items);
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Directory not found' });
    res.status(500).json({ error: err.message });
  }
});

// --- API: Upload files ---

router.post('/api/upload', upload.array('files', 100), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }
  res.json({ uploaded: req.files.map(f => f.originalname) });
});

// --- API: Download file ---

router.get('/api/download', (req, res) => {
  const filePath = safePath(req.query.path);
  if (!filePath) return res.status(400).json({ error: 'Invalid path' });

  if (!fsSync.existsSync(filePath) || fsSync.statSync(filePath).isDirectory()) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.download(filePath);
});

// --- API: Download multiple files as zip ---

router.post('/api/download-batch', express.json(), async (req, res) => {
  const paths = req.body && req.body.paths;
  if (!Array.isArray(paths) || paths.length === 0) {
    return res.status(400).json({ error: 'No paths provided' });
  }
  if (paths.length > 500) {
    return res.status(400).json({ error: 'Too many items' });
  }

  // Validate all paths first
  const resolved = [];
  for (const p of paths) {
    const target = safePath(p);
    if (!target || target === BASE_DIR) {
      return res.status(400).json({ error: `Invalid path: ${p}` });
    }
    try {
      const stat = await fs.stat(target);
      resolved.push({ rel: p, abs: target, isDir: stat.isDirectory() });
    } catch {
      return res.status(404).json({ error: `Not found: ${p}` });
    }
  }

  const zipName = resolved.length === 1
    ? path.basename(resolved[0].abs) + '.zip'
    : 'filedrop-download.zip';

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);

  const archive = archiver('zip', { zlib: { level: 5 } });
  archive.on('error', err => {
    if (!res.headersSent) res.status(500).json({ error: err.message });
    else res.end();
  });
  archive.pipe(res);

  for (const item of resolved) {
    const name = path.basename(item.abs);
    if (item.isDir) {
      archive.directory(item.abs, name);
    } else {
      archive.file(item.abs, { name });
    }
  }

  archive.finalize();
});

// --- API: Rename file or folder ---

router.patch('/api/files', express.json(), async (req, res) => {
  const target = safePath(req.query.path);
  if (!target) return res.status(400).json({ error: 'Invalid path' });
  if (target === BASE_DIR) return res.status(400).json({ error: 'Cannot rename root directory' });

  const newName = req.body && req.body.name;
  if (!newName || newName.includes('/') || newName.includes('..')) {
    return res.status(400).json({ error: 'Invalid name' });
  }

  const newPath = path.join(path.dirname(target), newName);
  // Validate the new path is still within BASE_DIR
  if (!newPath.startsWith(BASE_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  if (newPath === SELF_DIR || newPath.startsWith(SELF_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid path' });
  }

  try {
    await fs.access(target);
    try {
      await fs.access(newPath);
      return res.status(409).json({ error: 'A file or folder with that name already exists' });
    } catch {}
    await fs.rename(target, newPath);
    res.json({ renamed: newName });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Not found' });
    res.status(500).json({ error: err.message });
  }
});

// --- API: Bulk delete ---

router.post('/api/delete-batch', express.json(), async (req, res) => {
  const paths = req.body && req.body.paths;
  if (!Array.isArray(paths) || paths.length === 0) {
    return res.status(400).json({ error: 'No paths provided' });
  }
  if (paths.length > 500) {
    return res.status(400).json({ error: 'Too many items' });
  }

  const results = { deleted: [], errors: [] };
  for (const p of paths) {
    const target = safePath(p);
    if (!target || target === BASE_DIR) {
      results.errors.push({ path: p, error: 'Invalid path' });
      continue;
    }
    try {
      const stat = await fs.stat(target);
      if (stat.isDirectory()) {
        await fs.rm(target, { recursive: true });
      } else {
        await fs.unlink(target);
      }
      results.deleted.push(p);
    } catch (err) {
      results.errors.push({ path: p, error: err.message });
    }
  }
  res.json(results);
});

// --- API: Delete file or folder ---

router.delete('/api/files', async (req, res) => {
  const target = safePath(req.query.path);
  if (!target) return res.status(400).json({ error: 'Invalid path' });
  if (target === BASE_DIR) return res.status(400).json({ error: 'Cannot delete root directory' });

  try {
    const stat = await fs.stat(target);
    if (stat.isDirectory()) {
      await fs.rm(target, { recursive: true });
    } else {
      await fs.unlink(target);
    }
    res.json({ deleted: path.basename(target) });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Not found' });
    res.status(500).json({ error: err.message });
  }
});

// --- API: Create directory ---

router.post('/api/mkdir', express.json(), async (req, res) => {
  const parentPath = req.query.path || '';
  const name = req.body && req.body.name;
  if (!name || name.includes('/') || name.includes('..')) {
    return res.status(400).json({ error: 'Invalid folder name' });
  }
  const dir = safePath(path.join(parentPath, name));
  if (!dir) return res.status(400).json({ error: 'Invalid path' });

  try {
    await fs.mkdir(dir, { recursive: false });
    res.json({ created: name });
  } catch (err) {
    if (err.code === 'EEXIST') return res.status(409).json({ error: 'Already exists' });
    res.status(500).json({ error: err.message });
  }
});

// --- Error handler for multer ---

router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(500).json({ error: err.message });
  }
});

// --- Mount router at both / and /filedrop ---

app.use('/', router);
app.use('/filedrop', router);

// --- Start ---

app.listen(PORT, '0.0.0.0', () => {
  console.log(`FileDrop running at http://0.0.0.0:${PORT}`);
  console.log(`Serving files from ${BASE_DIR}`);
});
