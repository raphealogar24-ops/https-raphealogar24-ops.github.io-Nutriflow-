import crypto from 'crypto';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const ADMIN_EMAIL = 'raphealogar24@gmail.com';
const DEFAULT_INITIAL_PASSWORD = process.env.ADMIN_PASSCODE || '8144899449';

app.use(express.json({ limit: '10mb' }));

const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const ADMIN_AUTH_FILE = path.join(DATA_DIR, 'admin_auth.json');

// Active server-verified admin session tokens
const activeAdminSessions = new Set();

// Active Server-Sent Events (SSE) clients for real-time catalog sync
const sseClients = new Set();

function broadcastCatalogUpdate(productsList) {
  const payload = JSON.stringify({
    type: 'catalog_sync',
    syncedAt: new Date().toISOString(),
    products: productsList
  });
  for (const client of sseClients) {
    try {
      client.write(`data: ${payload}\n\n`);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(String(password), salt, 10000, 64, 'sha512').toString('hex');
}

function readAdminAuthConfig() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (fs.existsSync(ADMIN_AUTH_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(ADMIN_AUTH_FILE, 'utf8'));
      if (parsed && parsed.salt && parsed.passwordHash) {
        return parsed;
      }
    }
  } catch (err) {
    console.error('Error reading admin auth file:', err);
  }
  return null;
}

function verifyAdminPassword(inputPassword) {
  const clean = String(inputPassword || '').trim();
  if (!clean) return false;

  const customAuth = readAdminAuthConfig();
  if (customAuth) {
    const computed = hashPassword(clean, customAuth.salt);
    return crypto.timingSafeEqual(
      Buffer.from(computed, 'hex'),
      Buffer.from(customAuth.passwordHash, 'hex')
    );
  }

  // Initial password before custom password is set
  return clean === DEFAULT_INITIAL_PASSWORD || clean === 'admin1234';
}

function saveCustomAdminPassword(newPassword) {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(newPassword, salt);
  const record = {
    email: ADMIN_EMAIL,
    salt,
    passwordHash,
    updatedAt: new Date().toISOString()
  };
  fs.writeFileSync(ADMIN_AUTH_FILE, JSON.stringify(record, null, 2), 'utf8');
}

app.post('/api/admin/login', (req, res) => {
  const { email, password, passcode } = req.body || {};
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanPassword = String(password ?? passcode ?? '').trim();

  if (cleanEmail !== ADMIN_EMAIL) {
    return res.status(403).json({
      error: 'Access denied: Only the store admin email (raphealogar24@gmail.com) is authorized.'
    });
  }

  if (!verifyAdminPassword(cleanPassword)) {
    const hasCustom = Boolean(readAdminAuthConfig());
    return res.status(401).json({
      error: hasCustom
        ? 'Incorrect admin password. Please enter your custom admin password.'
        : 'Incorrect admin password. Default password is your store number (8144899449).'
    });
  }

  const sessionToken = `adm_${crypto.randomBytes(24).toString('hex')}`;
  activeAdminSessions.add(sessionToken);

  return res.json({
    success: true,
    email: ADMIN_EMAIL,
    token: sessionToken,
    hasCustomPassword: Boolean(readAdminAuthConfig())
  });
});

app.get('/api/admin/session', (req, res) => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ authenticated: false });
  }
  const token = authHeader.slice(7).trim();
  if (!token || !activeAdminSessions.has(token)) {
    return res.status(401).json({ authenticated: false });
  }
  return res.json({
    authenticated: true,
    email: ADMIN_EMAIL,
    hasCustomPassword: Boolean(readAdminAuthConfig())
  });
});

app.post('/api/admin/logout', (req, res) => {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    activeAdminSessions.delete(token);
  }
  res.json({ success: true });
});

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Admin password login required.' });
  }
  const token = authHeader.slice(7).trim();
  if (!token || !activeAdminSessions.has(token)) {
    return res.status(401).json({ error: 'Admin session expired or locked. Please log in with your password.' });
  }
  req.adminUser = { email: ADMIN_EMAIL, emailVerified: true };
  next();
}

app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const cleanCurrent = String(currentPassword || '').trim();
  const cleanNew = String(newPassword || '').trim();

  if (!verifyAdminPassword(cleanCurrent)) {
    return res.status(401).json({ error: 'Current admin password is incorrect.' });
  }

  if (cleanNew.length < 4 || cleanNew.length > 64) {
    return res.status(400).json({ error: 'New password must be between 4 and 64 characters.' });
  }

  saveCustomAdminPassword(cleanNew);
  return res.json({
    success: true,
    message: 'Admin password updated successfully.'
  });
});

const DEFAULT_PRODUCTS = [
  {
    id: 'prod_1',
    name: 'Tiger Nut Milk',
    category: 'Non-Carbonated',
    description: 'Rich, creamy blend of fresh tiger nuts, dates, and coconut extract. Served ice-cold and naturally sweetened.',
    price: 800,
    emoji: '🥛',
    imageUrl: '',
    isPublished: true
  },
  {
    id: 'prod_2',
    name: 'Fanta Orange',
    category: 'Carbonated',
    description: 'Crisp, sparkling orange soda served chilled for instant refreshment.',
    price: 500,
    emoji: '🧡',
    imageUrl: '',
    isPublished: true
  },
  {
    id: 'prod_3',
    name: 'Sprite',
    category: 'Carbonated',
    description: 'Refreshing lemon-lime sparkling drink served ice-cold.',
    price: 500,
    emoji: '🟢',
    imageUrl: '',
    isPublished: true
  },
  {
    id: 'prod_4',
    name: 'Coca-Cola',
    category: 'Carbonated',
    description: 'Classic ice-cold Coca-Cola with bold, refreshing taste.',
    price: 500,
    emoji: '🔴',
    imageUrl: '',
    isPublished: true
  },
  {
    id: 'prod_5',
    name: 'Zobo Juice',
    category: 'Non-Carbonated',
    description: 'Traditional hibiscus flower drink infused with natural ginger, pineapple, and cloves.',
    price: 400,
    emoji: '🍷',
    imageUrl: '',
    isPublished: true
  },
  {
    id: 'prod_6',
    name: 'Yogurt Drink',
    category: 'Dairy',
    description: 'Smooth, probiotic-rich sweetened yogurt drink made from fresh dairy.',
    price: 1200,
    emoji: '🥄',
    imageUrl: '',
    isPublished: true
  },
  {
    id: 'prod_7',
    name: 'Bottled Water',
    category: 'Water',
    description: 'Pure, chilled table water for clean everyday hydration.',
    price: 200,
    emoji: '💧',
    imageUrl: '',
    isPublished: true
  }
];

function readProducts() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(PRODUCTS_FILE)) {
      fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(DEFAULT_PRODUCTS, null, 2), 'utf8');
      return DEFAULT_PRODUCTS;
    }
    const raw = fs.readFileSync(PRODUCTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : DEFAULT_PRODUCTS;
  } catch (err) {
    console.error('Error reading products file:', err);
    return DEFAULT_PRODUCTS;
  }
}

function writeProducts(products) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2), 'utf8');
  } catch (err) {
    console.error('Error writing products file:', err);
  }
}

function sanitizeProductItem(raw, fallbackId) {
  const id = String(raw?.id || fallbackId || `prod_${Date.now()}`).replace(/[^a-zA-Z0-9_-]/g, '');
  const name = String(raw?.name || '').trim().slice(0, 100);
  const category = String(raw?.category || 'General').trim().slice(0, 60) || 'General';
  const description = String(raw?.description || '').trim().slice(0, 1000);
  const price = Math.max(0, Math.min(10000000, Number(raw?.price) || 0));
  const emoji = String(raw?.emoji || '🥤').trim().slice(0, 16) || '🥤';
  const imageUrl = String(raw?.imageUrl || '').slice(0, 300000);
  return {
    id,
    name,
    category,
    description,
    price,
    emoji,
    imageUrl,
    isPublished: true,
    updatedAt: raw?.updatedAt || new Date().toISOString()
  };
}

app.get('/api/products', (req, res) => {
  res.json(readProducts());
});

// Real-time Server-Sent Events stream for instant catalog sync across tabs/devices
app.get('/api/products/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const initialPayload = JSON.stringify({
    type: 'catalog_sync',
    syncedAt: new Date().toISOString(),
    products: readProducts()
  });
  res.write(`data: ${initialPayload}\n\n`);

  sseClients.add(res);

  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

// Full catalog sync endpoint (Admin only)
app.post('/api/products/sync', requireAdmin, (req, res) => {
  const incomingList = Array.isArray(req.body?.products) ? req.body.products : null;
  if (!incomingList) {
    return res.status(400).json({ error: 'Invalid products array for sync.' });
  }

  const nowIso = new Date().toISOString();
  const sanitizedList = [];
  const seenIds = new Set();

  for (const item of incomingList) {
    const clean = sanitizeProductItem(item);
    if (!clean.name || seenIds.has(clean.id)) continue;
    clean.updatedAt = nowIso;
    seenIds.add(clean.id);
    sanitizedList.push(clean);
  }

  if (sanitizedList.length > 0) {
    writeProducts(sanitizedList);
    broadcastCatalogUpdate(sanitizedList);
    return res.json({
      success: true,
      syncedAt: nowIso,
      count: sanitizedList.length,
      products: sanitizedList
    });
  }

  const current = readProducts();
  return res.json({
    success: true,
    syncedAt: nowIso,
    count: current.length,
    products: current
  });
});

app.post('/api/products', requireAdmin, (req, res) => {
  const products = readProducts();
  const body = req.body || {};
  const newProduct = sanitizeProductItem(body);
  newProduct.updatedAt = new Date().toISOString();

  if (!newProduct.name) {
    return res.status(400).json({ error: 'Product name is required.' });
  }

  const existingIndex = products.findIndex((p) => String(p.id) === newProduct.id);
  if (existingIndex >= 0) {
    products[existingIndex] = { ...products[existingIndex], ...newProduct };
  } else {
    products.unshift(newProduct);
  }

  writeProducts(products);
  broadcastCatalogUpdate(products);
  res.json(newProduct);
});

app.put('/api/products/:id', requireAdmin, (req, res) => {
  const products = readProducts();
  const id = String(req.params.id);
  const idx = products.findIndex((p) => String(p.id) === id);
  const body = req.body || {};
  const base = idx >= 0 ? products[idx] : {};

  const updated = sanitizeProductItem(
    {
      ...base,
      ...body,
      id,
      updatedAt: new Date().toISOString()
    },
    id
  );

  if (!updated.name) {
    return res.status(400).json({ error: 'Product name is required.' });
  }

  if (idx >= 0) {
    products[idx] = { ...products[idx], ...updated };
  } else {
    products.unshift(updated);
  }

  writeProducts(products);
  broadcastCatalogUpdate(products);
  res.json(updated);
});

app.delete('/api/products/:id', requireAdmin, (req, res) => {
  const products = readProducts();
  const id = String(req.params.id);
  const filtered = products.filter((p) => String(p.id) !== id);
  writeProducts(filtered);
  broadcastCatalogUpdate(filtered);
  res.json({ success: true, id });
});

app.use(express.static(__dirname));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
