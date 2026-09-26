import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const ADMIN_EMAIL = 'raphealogar24@gmail.com';

app.use(express.json({ limit: '10mb' }));

const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const FIREBASE_CONFIG_FILE = path.join(__dirname, 'firebase-applet-config.json');

function getFirebaseApiKey() {
  try {
    if (fs.existsSync(FIREBASE_CONFIG_FILE)) {
      const cfg = JSON.parse(fs.readFileSync(FIREBASE_CONFIG_FILE, 'utf8'));
      return cfg.apiKey || '';
    }
  } catch (err) {
    console.error('Could not read firebase config:', err);
  }
  return '';
}

async function requireAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Admin authentication required.' });
    }
    const idToken = authHeader.slice(7).trim();
    const apiKey = getFirebaseApiKey();
    if (!idToken || !apiKey) {
      return res.status(401).json({ error: 'Invalid authentication configuration.' });
    }

    const verifyRes = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      }
    );

    if (!verifyRes.ok) {
      return res.status(401).json({ error: 'Invalid or expired admin session.' });
    }

    const data = await verifyRes.json();
    const user = data?.users?.[0];
    if (!user || !user.emailVerified || String(user.email || '').toLowerCase() !== ADMIN_EMAIL) {
      return res.status(403).json({ error: 'Forbidden: Only the store admin can upload or edit goods.' });
    }

    req.adminUser = user;
    next();
  } catch (err) {
    console.error('Admin verification error:', err);
    return res.status(500).json({ error: 'Failed to verify admin permissions.' });
  }
}

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

app.get('/api/products', (req, res) => {
  res.json(readProducts());
});

app.post('/api/products', requireAdmin, (req, res) => {
  const products = readProducts();
  const body = req.body || {};
  const id = String(body.id || `prod_${Date.now()}`).replace(/[^a-zA-Z0-9_-]/g, '');
  const name = String(body.name || '').trim().slice(0, 100);
  const category = String(body.category || 'General').trim().slice(0, 60);
  const description = String(body.description || '').trim().slice(0, 1000);
  const price = Math.max(0, Math.min(10000000, Number(body.price) || 0));
  const emoji = String(body.emoji || '🥤').trim().slice(0, 16) || '🥤';
  const imageUrl = String(body.imageUrl || '').slice(0, 300000);

  if (!name) {
    return res.status(400).json({ error: 'Product name is required.' });
  }

  const newProduct = {
    id,
    name,
    category,
    description,
    price,
    emoji,
    imageUrl,
    isPublished: true,
    updatedAt: new Date().toISOString()
  };

  const existingIndex = products.findIndex((p) => String(p.id) === id);
  if (existingIndex >= 0) {
    products[existingIndex] = { ...products[existingIndex], ...newProduct };
  } else {
    products.unshift(newProduct);
  }

  writeProducts(products);
  res.json(newProduct);
});

app.put('/api/products/:id', requireAdmin, (req, res) => {
  const products = readProducts();
  const id = String(req.params.id);
  const idx = products.findIndex((p) => String(p.id) === id);
  const body = req.body || {};

  const updated = {
    id,
    name: String(body.name ?? (idx >= 0 ? products[idx].name : '')).trim().slice(0, 100),
    category: String(body.category ?? (idx >= 0 ? products[idx].category : 'General')).trim().slice(0, 60),
    description: String(body.description ?? (idx >= 0 ? products[idx].description : '')).trim().slice(0, 1000),
    price: Math.max(0, Math.min(10000000, Number(body.price ?? (idx >= 0 ? products[idx].price : 0)) || 0)),
    emoji: String(body.emoji ?? (idx >= 0 ? products[idx].emoji : '🥤')).trim().slice(0, 16) || '🥤',
    imageUrl: String(body.imageUrl ?? (idx >= 0 ? products[idx].imageUrl : '')).slice(0, 300000),
    isPublished: true,
    updatedAt: new Date().toISOString()
  };

  if (!updated.name) {
    return res.status(400).json({ error: 'Product name is required.' });
  }

  if (idx >= 0) {
    products[idx] = { ...products[idx], ...updated };
  } else {
    products.unshift(updated);
  }

  writeProducts(products);
  res.json(updated);
});

app.delete('/api/products/:id', requireAdmin, (req, res) => {
  const products = readProducts();
  const id = String(req.params.id);
  const filtered = products.filter((p) => String(p.id) !== id);
  writeProducts(filtered);
  res.json({ success: true, id });
});

app.use(['/_sdk', '/cdn-cgi'], (req, res) => {
  res.type('application/javascript').send('');
});

app.use(express.static(__dirname));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
