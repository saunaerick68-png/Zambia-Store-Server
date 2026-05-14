require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const { Pool } = require('pg');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const rateLimit = require('express-rate-limit');
const multer = require('multer');

// ─── Startup env check ───────────────────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error('[FATAL] DATABASE_URL environment variable is not set.');
  console.error('        Go to Render → your service → Environment and add DATABASE_URL.');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '3462Abel';

// ─── Trust proxy (Render / Railway sit behind one) ───────────────────────────
app.set('trust proxy', 1);

// ─── Security & Performance Middleware ───────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());
app.use(morgan('combined'));

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: true,          // reflect request origin — allows file:// and any host
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// ─── Body parsers ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// ─── Rate limiting ───────────────────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' },
});
const orderLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Too many orders from this IP. Please wait before trying again.' },
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many login attempts. Please wait 15 minutes.' },
});
app.use('/api/', generalLimiter);

// ─── Database Pool ────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB POOL ERROR]', err.message);
});

async function dbQuery(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

// ─── Session Store ────────────────────────────────────────────────────────────
const PgSession = connectPgSimple(session);
const pgStore = new PgSession({
  pool,
  tableName: 'session',
  createTableIfMissing: true,
  pruneSessionInterval: 60 * 15,
});
pgStore.on('error', (err) => {
  console.error('[SESSION STORE ERROR]', err.message);
});
app.use(session({
  store: pgStore,
  secret: process.env.SESSION_SECRET || 'zmafrdeal-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'zm.sid',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 10 * 60 * 60 * 1000, // 10 hours
  },
}));

// ─── Multer (memory → base64 in DB) ──────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only image files allowed.'));
    cb(null, true);
  },
});
const productUpload = upload.fields([
  { name: 'store_image', maxCount: 1 },
  { name: 'carousel_images', maxCount: 12 },
  { name: 'detail_images', maxCount: 20 },
]);

function filesToBase64(files) {
  if (!files || !files.length) return [];
  return files.map(f => `data:${f.mimetype};base64,${f.buffer.toString('base64')}`);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) return next();
  return res.status(401).json({ success: false, error: 'Unauthorized. Admin login required.' });
}

function sendError(res, code, message, detail = null) {
  console.error(`[${code}]`, message, detail || '');
  return res.status(code).json({
    success: false,
    error: message,
    ...(detail ? { detail } : {}),
  });
}

function parseJsonField(val, fallback = []) {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try { return JSON.parse(val); } catch { return fallback; }
  }
  return fallback;
}

// ─── DB Init ──────────────────────────────────────────────────────────────────
async function initDB() {
  try {
    // Ensure gen_random_uuid() is available (needed for PostgreSQL < 13)
    // Wrapped in catch so a permission error never kills the rest of initDB
    await dbQuery(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`).catch(() => {});
    await dbQuery(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`).catch(() => {});

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS categories (
        id   SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        slug TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Backfill unique constraints on existing tables created before they were added
    await dbQuery(`
      DO $$ BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'categories_slug_key'
        ) THEN
          ALTER TABLE categories ADD CONSTRAINT categories_slug_key UNIQUE (slug);
        END IF;
      END $$;
    `);
    await dbQuery(`
      DO $$ BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'categories_name_key'
        ) THEN
          ALTER TABLE categories ADD CONSTRAINT categories_name_key UNIQUE (name);
        END IF;
      END $$;
    `);

    await dbQuery(`
      INSERT INTO categories (name, slug) VALUES
        ('All',         'all'),
        ('Electronics', 'electronics'),
        ('Fashion',     'fashion'),
        ('Bags',        'bags'),
        ('Jewelry',     'jewelry'),
        ('Beauty',      'beauty'),
        ('Home',        'home'),
        ('Sports',      'sports'),
        ('Kids',        'kids'),
        ('Other',       'other')
      ON CONFLICT (slug) DO NOTHING;
    `);

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS products (
        id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name             TEXT NOT NULL,
        description      TEXT,
        category_slug    TEXT DEFAULT 'other',
        price            NUMERIC(12,2) NOT NULL,
        previous_price   NUMERIC(12,2),
        save_amount      NUMERIC(12,2) DEFAULT 0,
        badge            TEXT DEFAULT 'HOT',
        show_badge       BOOLEAN DEFAULT TRUE,
        position_order   INT DEFAULT 99,
        stock            INT DEFAULT 0,
        sales            INT DEFAULT 0,
        discount         NUMERIC(12,2) DEFAULT 0,
        shipping_fee     NUMERIC(12,2) DEFAULT 0,
        store_image      TEXT,
        carousel_images  JSONB DEFAULT '[]',
        detail_images    JSONB DEFAULT '[]',
        is_active        BOOLEAN DEFAULT TRUE,
        created_at       TIMESTAMPTZ DEFAULT NOW(),
        updated_at       TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Fix existing products table: restore id DEFAULT and add missing columns
    await dbQuery(`
      ALTER TABLE products ALTER COLUMN id SET DEFAULT gen_random_uuid();
    `).catch(() => {});
    await dbQuery(`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS category_slug TEXT DEFAULT 'other';
    `).catch(() => {});

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS reviews (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        product_id    UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        customer_name TEXT NOT NULL,
        rating        SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment       TEXT,
        is_approved   BOOLEAN DEFAULT FALSE,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await dbQuery(`ALTER TABLE reviews ALTER COLUMN id SET DEFAULT gen_random_uuid();`).catch(() => {});

    // Backfill columns that were added after the initial reviews table was created
    await dbQuery(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT FALSE;`).catch(() => {});
    await dbQuery(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();`).catch(() => {});
    await dbQuery(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS comment TEXT;`).catch(() => {});

    await dbQuery(`CREATE INDEX IF NOT EXISTS idx_reviews_product ON reviews(product_id);`);

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS orders (
        id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        order_number   TEXT NOT NULL UNIQUE,
        product_id     UUID REFERENCES products(id) ON DELETE SET NULL,
        product_name   TEXT,
        product_image  TEXT,
        quantity       INT DEFAULT 1,
        unit_price     NUMERIC(12,2),
        subtotal       NUMERIC(12,2),
        discount       NUMERIC(12,2) DEFAULT 0,
        shipping       NUMERIC(12,2) DEFAULT 0,
        total          NUMERIC(12,2),
        payment_method TEXT DEFAULT 'pay_after',
        customer_name  TEXT,
        phone          TEXT,
        backup_phone   TEXT,
        whatsapp       TEXT,
        email          TEXT,
        country        TEXT DEFAULT 'Zambia',
        city           TEXT,
        address1       TEXT,
        address2       TEXT,
        remark         TEXT,
        status         TEXT DEFAULT 'pending',
        is_read        BOOLEAN DEFAULT FALSE,
        created_at     TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await dbQuery(`ALTER TABLE orders ALTER COLUMN id SET DEFAULT gen_random_uuid();`).catch(() => {});

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS notifications (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        order_id      UUID REFERENCES orders(id) ON DELETE CASCADE,
        message       TEXT,
        customer_name TEXT,
        phone         TEXT,
        is_read       BOOLEAN DEFAULT FALSE,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await dbQuery(`ALTER TABLE notifications ALTER COLUMN id SET DEFAULT gen_random_uuid();`).catch(() => {});

    // New product columns: specifications, how_to_use, available_colors
    await dbQuery(`ALTER TABLE products ADD COLUMN IF NOT EXISTS specifications JSONB DEFAULT '[]';`).catch(() => {});
    await dbQuery(`ALTER TABLE products ADD COLUMN IF NOT EXISTS how_to_use TEXT;`).catch(() => {});
    await dbQuery(`ALTER TABLE products ADD COLUMN IF NOT EXISTS available_colors JSONB DEFAULT '[]';`).catch(() => {});

    // New order column: selected_color
    await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS selected_color TEXT;`).catch(() => {});

    console.log('[DB] All tables ready.');
  } catch (err) {
    console.error('[DB INIT ERROR]', err.message);
  }
}
initDB();

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN AUTH
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return sendError(res, 400, 'Password is required.');
    if (password !== ADMIN_PASSWORD) {
      console.warn('[AUTH] Failed admin login attempt from', req.ip);
      return sendError(res, 401, 'Incorrect password.');
    }
    if (!req.session) {
      return sendError(res, 500, 'Session unavailable. Check DATABASE_URL and SESSION_SECRET env vars on Render.');
    }
    req.session.isAdmin = true;
    req.session.loginAt = new Date().toISOString();
    req.session.ip = req.ip;
    req.session.save(err => {
      if (err) {
        console.error('[SESSION SAVE]', err.message);
        return sendError(res, 500, 'Session could not be saved: ' + err.message);
      }
      return res.json({ success: true, message: 'Authenticated.' });
    });
  } catch (err) {
    return sendError(res, 500, 'Login error: ' + err.message, err.message);
  }
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  req.session.destroy(err => {
    if (err) return sendError(res, 500, 'Logout failed.', err.message);
    res.clearCookie('zm.sid');
    return res.json({ success: true });
  });
});

app.get('/api/admin/check', (req, res) => {
  return res.json({
    isAdmin: !!(req.session && req.session.isAdmin === true),
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/categories', async (req, res) => {
  try {
    const result = await dbQuery('SELECT * FROM categories ORDER BY id ASC');
    return res.json({ success: true, categories: result.rows });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch categories.', err.message);
  }
});

app.post('/api/categories', requireAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name) return sendError(res, 400, 'Category name is required.');
  const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
  try {
    const result = await dbQuery(
      'INSERT INTO categories (name, slug) VALUES ($1, $2) ON CONFLICT (slug) DO NOTHING RETURNING *',
      [name.trim(), slug]
    );
    if (!result.rows.length) return sendError(res, 409, 'Category already exists.');
    return res.json({ success: true, category: result.rows[0] });
  } catch (err) {
    return sendError(res, 500, 'Failed to create category.', err.message);
  }
});

app.delete('/api/categories/:id', requireAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM categories WHERE id=$1 AND slug != \'all\'', [req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendError(res, 500, 'Failed to delete category.', err.message);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/products', async (req, res) => {
  try {
    const { search, category, page = 1, limit = 50, include_inactive } = req.query;
    const isAdmin = req.session && req.session.isAdmin;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const conditions = [];
    const params = [];

    if (!isAdmin || include_inactive !== 'true') {
      conditions.push('p.is_active = TRUE');
    }
    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(p.name ILIKE $${params.length} OR p.description ILIKE $${params.length})`);
    }
    if (category && category !== 'all') {
      params.push(category);
      conditions.push(`p.category_slug = $${params.length}`);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    params.push(parseInt(limit));
    params.push(offset);

    const sql = `
      SELECT p.*,
             COALESCE(AVG(r.rating) FILTER (WHERE r.is_approved = TRUE), 0) AS avg_rating,
             COUNT(r.id) FILTER (WHERE r.is_approved = TRUE) AS review_count
      FROM products p
      LEFT JOIN reviews r ON r.product_id = p.id
      ${where}
      GROUP BY p.id
      ORDER BY p.position_order ASC, p.created_at DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const countSql = `SELECT COUNT(*) FROM products p ${where.replace(/\$(\d+)/g, (m, n) => '$' + n)}`;
    const countParams = params.slice(0, -2);

    const [result, countResult] = await Promise.all([
      dbQuery(sql, params),
      dbQuery(countSql, countParams),
    ]);

    return res.json({
      success: true,
      products: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch products.', err.message);
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const result = await dbQuery(`
      SELECT p.*,
             COALESCE(AVG(r.rating) FILTER (WHERE r.is_approved = TRUE), 0) AS avg_rating,
             COUNT(r.id) FILTER (WHERE r.is_approved = TRUE) AS review_count
      FROM products p
      LEFT JOIN reviews r ON r.product_id = p.id
      WHERE p.id = $1
      GROUP BY p.id
    `, [req.params.id]);
    if (!result.rows.length) return sendError(res, 404, 'Product not found.');
    return res.json({ success: true, product: result.rows[0] });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch product.', err.message);
  }
});

// Create product
app.post('/api/products', requireAdmin, (req, res) => {
  const isMultipart = (req.headers['content-type'] || '').includes('multipart/form-data');
  const handle = async (uploadErr) => {
    if (uploadErr) return sendError(res, 400, 'Upload error: ' + uploadErr.message);
    try {
      const b = req.body || {};
      if (!b.name || !b.price) return sendError(res, 400, 'Name and price are required.');

      let storeImage = b.store_image_url || null;
      if (req.files?.store_image?.[0]) {
        storeImage = `data:${req.files.store_image[0].mimetype};base64,${req.files.store_image[0].buffer.toString('base64')}`;
      }

      let carouselImages = parseJsonField(b.carousel_image_urls);
      if (req.files?.carousel_images?.length) {
        carouselImages = filesToBase64(req.files.carousel_images);
      }

      let detailImages = parseJsonField(b.detail_image_urls);
      if (req.files?.detail_images?.length) {
        detailImages = filesToBase64(req.files.detail_images);
      }

      const specs = parseJsonField(b.specifications);
      const colors = parseJsonField(b.available_colors);

      const result = await dbQuery(`
        INSERT INTO products
          (name, description, category_slug, price, previous_price, save_amount,
           badge, show_badge, position_order, stock, sales, discount, shipping_fee,
           store_image, carousel_images, detail_images, is_active,
           specifications, how_to_use, available_colors)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
        RETURNING *
      `, [
        b.name.trim(), b.description || '', b.category_slug || 'other',
        parseFloat(b.price), parseFloat(b.previous_price) || null,
        parseFloat(b.save_amount) || 0,
        b.badge || 'HOT', b.show_badge !== 'false',
        parseInt(b.position_order) || 99,
        parseInt(b.stock) || 0, parseInt(b.sales) || 0,
        parseFloat(b.discount) || 0, parseFloat(b.shipping_fee) || 0,
        storeImage, JSON.stringify(carouselImages), JSON.stringify(detailImages),
        b.is_active !== 'false',
        JSON.stringify(specs), b.how_to_use || null, JSON.stringify(colors),
      ]);

      return res.json({ success: true, product: result.rows[0], message: 'Product listed.' });
    } catch (err) {
      return sendError(res, 500, 'Failed to create product.', err.message);
    }
  };
  if (isMultipart) productUpload(req, res, handle);
  else handle(null);
});

// Update product
app.put('/api/products/:id', requireAdmin, (req, res) => {
  const isMultipart = (req.headers['content-type'] || '').includes('multipart/form-data');
  const handle = async (uploadErr) => {
    if (uploadErr) return sendError(res, 400, 'Upload error: ' + uploadErr.message);
    try {
      const existing = await dbQuery('SELECT * FROM products WHERE id=$1', [req.params.id]);
      if (!existing.rows.length) return sendError(res, 404, 'Product not found.');
      const old = existing.rows[0];
      const b = req.body || {};

      let storeImage = b.store_image_url !== undefined ? (b.store_image_url || old.store_image) : old.store_image;
      if (req.files?.store_image?.[0]) {
        storeImage = `data:${req.files.store_image[0].mimetype};base64,${req.files.store_image[0].buffer.toString('base64')}`;
      }

      let carouselImages = old.carousel_images;
      if (req.files?.carousel_images?.length) carouselImages = filesToBase64(req.files.carousel_images);
      else if (b.carousel_image_urls !== undefined) carouselImages = parseJsonField(b.carousel_image_urls);

      let detailImages = old.detail_images;
      if (req.files?.detail_images?.length) detailImages = filesToBase64(req.files.detail_images);
      else if (b.detail_image_urls !== undefined) detailImages = parseJsonField(b.detail_image_urls);

      const specs = b.specifications !== undefined ? parseJsonField(b.specifications) : parseJsonField(old.specifications);
      const colors = b.available_colors !== undefined ? parseJsonField(b.available_colors) : parseJsonField(old.available_colors);

      const result = await dbQuery(`
        UPDATE products SET
          name=$1, description=$2, category_slug=$3, price=$4, previous_price=$5,
          save_amount=$6, badge=$7, show_badge=$8, position_order=$9,
          stock=$10, sales=$11, discount=$12, shipping_fee=$13,
          store_image=$14, carousel_images=$15, detail_images=$16,
          specifications=$17, how_to_use=$18, available_colors=$19, updated_at=NOW()
        WHERE id=$20 RETURNING *
      `, [
        b.name || old.name,
        b.description !== undefined ? b.description : old.description,
        b.category_slug || old.category_slug,
        b.price ? parseFloat(b.price) : old.price,
        b.previous_price !== undefined ? (parseFloat(b.previous_price) || null) : old.previous_price,
        b.save_amount !== undefined ? parseFloat(b.save_amount) : old.save_amount,
        b.badge || old.badge,
        b.show_badge !== undefined ? b.show_badge !== 'false' : old.show_badge,
        b.position_order !== undefined ? parseInt(b.position_order) : old.position_order,
        b.stock !== undefined ? parseInt(b.stock) : old.stock,
        b.sales !== undefined ? parseInt(b.sales) : old.sales,
        b.discount !== undefined ? parseFloat(b.discount) : old.discount,
        b.shipping_fee !== undefined ? parseFloat(b.shipping_fee) : old.shipping_fee,
        storeImage, JSON.stringify(carouselImages), JSON.stringify(detailImages),
        JSON.stringify(specs),
        b.how_to_use !== undefined ? b.how_to_use : old.how_to_use,
        JSON.stringify(colors),
        req.params.id,
      ]);

      return res.json({ success: true, product: result.rows[0], message: 'Product updated.' });
    } catch (err) {
      return sendError(res, 500, 'Failed to update product.', err.message);
    }
  };
  if (isMultipart) productUpload(req, res, handle);
  else handle(null);
});

// Toggle active/hidden
app.patch('/api/products/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery(
      'UPDATE products SET is_active = NOT is_active, updated_at=NOW() WHERE id=$1 RETURNING id, name, is_active',
      [req.params.id]
    );
    if (!result.rows.length) return sendError(res, 404, 'Product not found.');
    const p = result.rows[0];
    return res.json({
      success: true,
      is_active: p.is_active,
      message: `"${p.name}" is now ${p.is_active ? 'visible' : 'hidden'} in store.`,
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to toggle product.', err.message);
  }
});

// Delete product
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery('DELETE FROM products WHERE id=$1 RETURNING name', [req.params.id]);
    if (!result.rows.length) return sendError(res, 404, 'Product not found.');
    return res.json({ success: true, message: `"${result.rows[0].name}" permanently deleted.` });
  } catch (err) {
    return sendError(res, 500, 'Failed to delete product.', err.message);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// REVIEWS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/reviews', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery(`
      SELECT r.*,
             p.name AS product_name,
             TO_CHAR(r.created_at::timestamptz, 'DD Mon YYYY') AS date_label
      FROM reviews r
      LEFT JOIN products p ON p.id = r.product_id
      ORDER BY r.created_at DESC
      LIMIT 500
    `);
    return res.json({ success: true, reviews: result.rows });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch reviews.', err.message);
  }
});

app.get('/api/products/:id/reviews', async (req, res) => {
  try {
    const isAdmin = req.session && req.session.isAdmin;
    const where = isAdmin ? 'WHERE r.product_id=$1' : 'WHERE r.product_id=$1 AND r.is_approved=TRUE';
    const result = await dbQuery(
      `SELECT r.*, TO_CHAR(r.created_at::timestamptz, 'DD Mon YYYY') AS date_label
       FROM reviews r ${where} ORDER BY r.created_at DESC`,
      [req.params.id]
    );
    return res.json({ success: true, reviews: result.rows });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch reviews.', err.message);
  }
});

// Fetch a single review by ID (used by submitters to check their own pending review)
app.get('/api/reviews/:id', async (req, res) => {
  try {
    const result = await dbQuery(
      `SELECT r.*, TO_CHAR(r.created_at::timestamptz, 'DD Mon YYYY') AS date_label
       FROM reviews r WHERE r.id=$1`,
      [req.params.id]
    );
    if (!result.rows.length) return sendError(res, 404, 'Review not found.');
    return res.json({ success: true, review: result.rows[0] });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch review.', err.message);
  }
});

const reviewLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5,
  message: { success: false, error: 'Too many reviews submitted. Try again later.' } });

app.post('/api/products/:id/reviews', reviewLimiter, async (req, res) => {
  try {
    const { customer_name, rating, comment } = req.body || {};
    if (!customer_name || !rating) return sendError(res, 400, 'Name and rating are required.');
    const r = parseInt(rating);
    if (r < 1 || r > 5) return sendError(res, 400, 'Rating must be between 1 and 5.');

    const check = await dbQuery('SELECT id FROM products WHERE id=$1 AND is_active=TRUE', [req.params.id]);
    if (!check.rows.length) return sendError(res, 404, 'Product not found.');

    const result = await dbQuery(
      'INSERT INTO reviews (product_id, customer_name, rating, comment) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.params.id, customer_name.trim().substring(0, 80), r, (comment || '').trim().substring(0, 500)]
    );
    return res.json({
      success: true,
      review: result.rows[0],
      message: 'Review submitted! It will appear after approval.',
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to submit review.', err.message);
  }
});

// Admin posts a review directly — auto-approved and immediately visible
app.post('/api/admin/products/:id/reviews', requireAdmin, async (req, res) => {
  try {
    const { customer_name, rating, comment } = req.body || {};
    if (!customer_name || !rating) return sendError(res, 400, 'Name and rating are required.');
    const r = parseInt(rating);
    if (r < 1 || r > 5) return sendError(res, 400, 'Rating must be between 1 and 5.');
    const check = await dbQuery('SELECT id FROM products WHERE id=$1', [req.params.id]);
    if (!check.rows.length) return sendError(res, 404, 'Product not found.');
    const result = await dbQuery(
      'INSERT INTO reviews (product_id, customer_name, rating, comment, is_approved) VALUES ($1,$2,$3,$4,TRUE) RETURNING *',
      [req.params.id, customer_name.trim().substring(0, 80), r, (comment || '').trim().substring(0, 500)]
    );
    return res.json({ success: true, review: result.rows[0], message: 'Review posted and live in store.' });
  } catch (err) {
    return sendError(res, 500, 'Failed to post review.', err.message);
  }
});

app.patch('/api/reviews/:id/approve', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery(
      'UPDATE reviews SET is_approved = TRUE WHERE id=$1 RETURNING id, is_approved',
      [req.params.id]
    );
    if (!result.rows.length) return sendError(res, 404, 'Review not found.');
    return res.json({ success: true, is_approved: true, message: 'Review approved and now visible to all users.' });
  } catch (err) {
    return sendError(res, 500, 'Failed to approve review.', err.message);
  }
});

app.patch('/api/reviews/:id/decline', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery(
      'UPDATE reviews SET is_approved = FALSE WHERE id=$1 RETURNING id, is_approved',
      [req.params.id]
    );
    if (!result.rows.length) return sendError(res, 404, 'Review not found.');
    return res.json({ success: true, is_approved: false, message: 'Review declined and hidden from store.' });
  } catch (err) {
    return sendError(res, 500, 'Failed to decline review.', err.message);
  }
});

app.delete('/api/reviews/:id', requireAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM reviews WHERE id=$1', [req.params.id]);
    return res.json({ success: true, message: 'Review deleted.' });
  } catch (err) {
    return sendError(res, 500, 'Failed to delete review.', err.message);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ORDERS
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/orders', orderLimiter, async (req, res) => {
  try {
    const b = req.body;
    if (!b.customer_name || !b.phone || !b.address1) {
      return sendError(res, 400, 'Full name, phone, and address are required.');
    }
    const orderNumber = `ZMF${Date.now()}${Math.floor(Math.random() * 9000 + 1000)}`;

    const result = await dbQuery(`
      INSERT INTO orders
        (order_number, product_id, product_name, product_image, quantity,
         unit_price, subtotal, discount, shipping, total, payment_method,
         customer_name, phone, backup_phone, whatsapp, email,
         country, city, address1, address2, remark, selected_color)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
      RETURNING *
    `, [
      orderNumber,
      b.product_id || null, b.product_name || 'Unknown', b.product_image || null,
      parseInt(b.quantity) || 1,
      parseFloat(b.unit_price) || 0, parseFloat(b.subtotal) || 0,
      parseFloat(b.discount) || 0, parseFloat(b.shipping) || 0, parseFloat(b.total) || 0,
      b.payment_method || 'pay_after',
      b.customer_name.trim(), b.phone.trim(),
      b.backup_phone || null, b.whatsapp || null, b.email || null,
      b.country || 'Zambia', b.city || null,
      b.address1.trim(), b.address2 || null, b.remark || null,
      b.selected_color || null,
    ]);

    const order = result.rows[0];

    // Notification
    await dbQuery(
      `INSERT INTO notifications (order_id, message, customer_name, phone)
       VALUES ($1,$2,$3,$4)`,
      [order.id,
       `New order #${orderNumber} — ${b.product_name || 'product'} x${b.quantity} — Total: K${parseFloat(b.total).toFixed(2)}`,
       b.customer_name.trim(), b.phone.trim()]
    );

    // Increment sales
    if (b.product_id) {
      await dbQuery('UPDATE products SET sales = sales + $1 WHERE id=$2', [parseInt(b.quantity) || 1, b.product_id]);
    }

    return res.json({ success: true, order, message: 'Order confirmed!' });
  } catch (err) {
    return sendError(res, 500, 'Failed to place order. Please try again.', err.message);
  }
});

// Public order tracking by phone number (no admin required)
app.get('/api/orders/track', async (req, res) => {
  const { phone } = req.query;
  if (!phone) return sendError(res, 400, 'Phone number is required.');
  try {
    // Normalise to the 9-digit core, then build every stored variant
    const core = phone.replace(/^\+?2600?/, '').replace(/^0/, '').replace(/\D/g, '');
    const variants = [
      '+260' + core,        // +260975967020  (standard)
      '+2600' + core,       // +2600975967020 (leading zero kept at checkout)
      '0' + core,           // 0975967020
      '260' + core,         // 260975967020
      core,                 // 975967020
      phone.trim(),         // whatever was passed verbatim
    ];
    const result = await dbQuery(
      `SELECT order_number, product_name, product_image, quantity, unit_price,
              subtotal, discount, shipping, total, payment_method,
              status, city, address1, created_at
       FROM orders WHERE phone = ANY($1::text[]) OR whatsapp = ANY($1::text[])
       ORDER BY created_at DESC LIMIT 30`,
      [variants]
    );
    return res.json({ success: true, orders: result.rows });
  } catch (err) {
    return sendError(res, 500, 'Failed to track orders.', err.message);
  }
});

app.get('/api/orders', requireAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 100 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const params = [];
    let where = '';
    if (status) { params.push(status); where = `WHERE status=$${params.length}`; }
    params.push(parseInt(limit), offset);
    const result = await dbQuery(
      `SELECT *, TO_CHAR(created_at::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at FROM orders ${where} ORDER BY created_at DESC LIMIT $${params.length-1} OFFSET $${params.length}`,
      params
    );
    const countResult = await dbQuery(`SELECT COUNT(*) FROM orders ${where}`, params.slice(0, -2));
    return res.json({ success: true, orders: result.rows, total: parseInt(countResult.rows[0].count) });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch orders.', err.message);
  }
});

app.patch('/api/orders/:id/status', requireAdmin, async (req, res) => {
  const valid = ['pending','confirmed','shipped','delivered','cancelled'];
  const { status } = req.body;
  if (!valid.includes(status)) return sendError(res, 400, 'Invalid status.');
  try {
    const result = await dbQuery('UPDATE orders SET status=$1 WHERE id=$2 RETURNING *', [status, req.params.id]);
    if (!result.rows.length) return sendError(res, 404, 'Order not found.');
    return res.json({ success: true, order: result.rows[0] });
  } catch (err) {
    return sendError(res, 500, 'Failed to update status.', err.message);
  }
});

app.delete('/api/orders/:id', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery('DELETE FROM orders WHERE id=$1 RETURNING order_number', [req.params.id]);
    if (!result.rows.length) return sendError(res, 404, 'Order not found.');
    return res.json({ success: true, message: `Order #${result.rows[0].order_number} deleted.` });
  } catch (err) {
    return sendError(res, 500, 'Failed to delete order.', err.message);
  }
});

// CSV export
app.get('/api/orders/export/csv', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery('SELECT * FROM orders ORDER BY created_at DESC');
    const cols = [
      'order_number','status','customer_name','phone','backup_phone','whatsapp','email',
      'country','city','address1','address2','remark',
      'product_name','quantity','unit_price','subtotal','discount','shipping','total',
      'payment_method','selected_color','created_at',
    ];
    const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const header = cols.join(',');
    const rows = result.rows.map(r => cols.map(c => escape(r[c])).join(','));
    const csv = [header, ...rows].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="zmafrdeal-orders-${Date.now()}.csv"`);
    return res.send(csv);
  } catch (err) {
    return sendError(res, 500, 'Failed to export orders.', err.message);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/notifications', requireAdmin, async (req, res) => {
  try {
    const result = await dbQuery(`
      SELECT
        n.id, n.order_id, n.message, n.customer_name, n.phone, n.is_read,
        TO_CHAR(n.created_at::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
        o.order_number, o.product_name, o.product_image, o.quantity,
        o.total, o.payment_method, o.city, o.address1, o.remark,
        o.whatsapp, o.selected_color, o.status
      FROM notifications n
      LEFT JOIN orders o ON o.id = n.order_id
      ORDER BY n.created_at DESC LIMIT 80
    `);
    const unreadCount = result.rows.filter(n => !n.is_read).length;
    return res.json({ success: true, notifications: result.rows, unreadCount });
  } catch (err) {
    return sendError(res, 500, 'Failed to fetch notifications.', err.message);
  }
});

app.patch('/api/notifications/read-all', requireAdmin, async (req, res) => {
  try {
    await dbQuery('UPDATE notifications SET is_read=TRUE WHERE is_read=FALSE');
    return res.json({ success: true });
  } catch (err) {
    return sendError(res, 500, 'Failed to mark notifications read.', err.message);
  }
});

app.patch('/api/notifications/:id/read', requireAdmin, async (req, res) => {
  try {
    await dbQuery('UPDATE notifications SET is_read=TRUE WHERE id=$1', [req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendError(res, 500, 'Failed to mark notification read.', err.message);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN STATS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [products, orders, revenue, pending, reviews] = await Promise.all([
      dbQuery('SELECT COUNT(*) FROM products WHERE is_active=TRUE'),
      dbQuery('SELECT COUNT(*) FROM orders'),
      dbQuery('SELECT COALESCE(SUM(total),0) AS total FROM orders WHERE status != \'cancelled\''),
      dbQuery('SELECT COUNT(*) FROM orders WHERE status=\'pending\''),
      dbQuery('SELECT COUNT(*) FROM reviews WHERE is_approved=FALSE'),
    ]);
    return res.json({
      success: true,
      stats: {
        activeProducts: parseInt(products.rows[0].count),
        totalOrders: parseInt(orders.rows[0].count),
        totalRevenue: parseFloat(revenue.rows[0].total),
        pendingOrders: parseInt(pending.rows[0].count),
        pendingReviews: parseInt(reviews.rows[0].count),
      },
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to load stats.', err.message);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SHAREABLE PRODUCT & CHECKOUT PAGES (for Facebook / social sharing)
// Set FRONTEND_URL env var on Render to your HTML's hosted URL.
// ═══════════════════════════════════════════════════════════════════════════════

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// /p/:id  →  product preview page with OG tags + redirect into app
app.get('/p/:id', async (req, res) => {
  try {
    const result = await dbQuery(
      `SELECT id, name, description, store_image, price, previous_price, save_amount
       FROM products WHERE id=$1 AND is_active=TRUE`,
      [req.params.id]
    );
    const frontendUrl = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
    if (!result.rows.length) return res.redirect(frontendUrl || '/');

    const p = result.rows[0];
    const targetUrl = `${frontendUrl}#product/${p.id}`;
    const title    = esc(p.name);
    const desc     = esc((p.description || 'Shop now on Zmafrdeal').substring(0, 200));
    const img      = p.store_image || '';
    const price    = `K ${parseFloat(p.price).toFixed(2)}`;
    const serverUrl = process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
    const ogUrl    = `${serverUrl}/p/${p.id}`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title} — Zmafrdeal</title>
  <!-- Open Graph (Facebook / WhatsApp / Twitter) -->
  <meta property="og:type"        content="product"/>
  <meta property="og:site_name"   content="Zmafrdeal"/>
  <meta property="og:title"       content="${title}"/>
  <meta property="og:description" content="${desc}"/>
  <meta property="og:url"         content="${ogUrl}"/>
  ${img ? `<meta property="og:image" content="${img}"/>
  <meta property="og:image:width"  content="800"/>
  <meta property="og:image:height" content="800"/>` : ''}
  <meta name="twitter:card"        content="summary_large_image"/>
  <meta name="twitter:title"       content="${title}"/>
  <meta name="twitter:description" content="${desc}"/>
  ${img ? `<meta name="twitter:image" content="${img}"/>` : ''}
  <meta http-equiv="refresh" content="0;url=${targetUrl}"/>
  <style>
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:Inter,sans-serif;background:#1a1a1a;color:#fff;
         display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
    .card{max-width:340px;width:100%;text-align:center;}
    img{width:100%;border-radius:14px;margin-bottom:16px;aspect-ratio:1;object-fit:cover;}
    .brand{font-size:13px;color:#c8a96e;font-weight:700;letter-spacing:1px;margin-bottom:10px;}
    .name{font-size:15px;font-weight:600;line-height:1.4;margin-bottom:12px;color:#f5f5f5;}
    .price{font-size:26px;font-weight:900;color:#e3001b;margin-bottom:18px;}
    .btn{display:inline-block;background:#c8a96e;color:#111;padding:14px 32px;
         border-radius:30px;text-decoration:none;font-weight:700;font-size:16px;}
    .sub{font-size:12px;color:#555;margin-top:12px;}
  </style>
</head>
<body>
  <div class="card">
    ${img ? `<img src="${img}" alt="${title}" onerror="this.style.display='none'"/>` : ''}
    <div class="brand">ZMAFRDEAL</div>
    <div class="name">${title}</div>
    <div class="price">${price}</div>
    <a class="btn" href="${targetUrl}">View Product →</a>
    <div class="sub">Redirecting automatically…</div>
  </div>
  <script>setTimeout(function(){window.location.href='${targetUrl}';},600);</script>
</body>
</html>`);
  } catch (err) {
    const frontendUrl = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
    return res.redirect(frontendUrl || '/');
  }
});

// /c/:id  →  checkout page with OG tags + redirect into app checkout
app.get('/c/:id', async (req, res) => {
  try {
    const result = await dbQuery(
      `SELECT id, name, description, store_image, price FROM products WHERE id=$1 AND is_active=TRUE`,
      [req.params.id]
    );
    const frontendUrl = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
    if (!result.rows.length) return res.redirect(frontendUrl || '/');

    const p = result.rows[0];
    const targetUrl = `${frontendUrl}#checkout/${p.id}`;
    const title    = esc(p.name);
    const desc     = esc(`Get it for K${parseFloat(p.price).toFixed(2)} — fast delivery across Zambia.`);
    const img      = p.store_image || '';
    const price    = `K ${parseFloat(p.price).toFixed(2)}`;
    const serverUrl = process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
    const ogUrl    = `${serverUrl}/c/${p.id}`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Buy Now: ${title} — Zmafrdeal</title>
  <meta property="og:type"        content="product"/>
  <meta property="og:site_name"   content="Zmafrdeal"/>
  <meta property="og:title"       content="Buy Now: ${title}"/>
  <meta property="og:description" content="${desc}"/>
  <meta property="og:url"         content="${ogUrl}"/>
  ${img ? `<meta property="og:image" content="${img}"/>
  <meta property="og:image:width"  content="800"/>
  <meta property="og:image:height" content="800"/>` : ''}
  <meta name="twitter:card"        content="summary_large_image"/>
  <meta name="twitter:title"       content="Buy Now: ${title}"/>
  <meta name="twitter:description" content="${desc}"/>
  ${img ? `<meta name="twitter:image" content="${img}"/>` : ''}
  <meta http-equiv="refresh" content="0;url=${targetUrl}"/>
  <style>
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:Inter,sans-serif;background:#1a1a1a;color:#fff;
         display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
    .card{max-width:340px;width:100%;text-align:center;}
    img{width:100%;border-radius:14px;margin-bottom:16px;aspect-ratio:1;object-fit:cover;}
    .brand{font-size:13px;color:#c8a96e;font-weight:700;letter-spacing:1px;margin-bottom:10px;}
    .name{font-size:15px;font-weight:600;line-height:1.4;margin-bottom:12px;color:#f5f5f5;}
    .price{font-size:26px;font-weight:900;color:#e3001b;margin-bottom:18px;}
    .btn{display:inline-block;background:#e3001b;color:#fff;padding:14px 32px;
         border-radius:30px;text-decoration:none;font-weight:700;font-size:16px;}
    .sub{font-size:12px;color:#555;margin-top:12px;}
  </style>
</head>
<body>
  <div class="card">
    ${img ? `<img src="${img}" alt="${title}" onerror="this.style.display='none'"/>` : ''}
    <div class="brand">ZMAFRDEAL</div>
    <div class="name">${title}</div>
    <div class="price">${price}</div>
    <a class="btn" href="${targetUrl}">Buy Now →</a>
    <div class="sub">Redirecting automatically…</div>
  </div>
  <script>setTimeout(function(){window.location.href='${targetUrl}';},600);</script>
</body>
</html>`);
  } catch (err) {
    const frontendUrl = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
    return res.redirect(frontendUrl || '/');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Global error handler
// ═══════════════════════════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('[UNHANDLED]', err);
  return res.status(500).json({
    success: false,
    error: 'Unexpected server error.',
    ...(process.env.NODE_ENV !== 'production' ? { detail: err.message } : {}),
  });
});

// 404 handler for unknown API routes
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route not found.' });
});

app.listen(PORT, () => {
  console.log(`[SERVER] Zmafrdeal v2 running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
});
