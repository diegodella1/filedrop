const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');

const app = express();
const router = express.Router();
const PORT = 3456;
const BASE_DIR = '/home/diego/Documents';
const SELF_DIR = path.join(BASE_DIR, 'filedrop');

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
