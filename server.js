const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection - uses DATABASE_URL from environment variables
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/ticketmanager',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'ticketmanager-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize database tables
async function initializeDatabase() {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        uuid TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        name TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Allowed emails table (whitelist)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS allowed_emails (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        added_by INTEGER,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(added_by) REFERENCES users(id)
      )
    `);
    
    // Tickets table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id SERIAL PRIMARY KEY,
        uuid TEXT UNIQUE,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'open',
        priority TEXT DEFAULT 'medium',
        created_by INTEGER,
        assigned_to INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(created_by) REFERENCES users(id),
        FOREIGN KEY(assigned_to) REFERENCES users(id)
      )
    `);
    
    // Ticket comments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ticket_comments (
        id SERIAL PRIMARY KEY,
        ticket_id INTEGER,
        user_id INTEGER,
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ticket_id) REFERENCES tickets(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);
    
    // Create default admin user if not exists
    const adminEmail = 'nidhin@platinumrx.in';
    const adminPassword = bcrypt.hashSync('Nidhin@007', 10);
    
    const userResult = await pool.query(
      "SELECT id FROM users WHERE email = $1", 
      [adminEmail]
    );
    
    if (userResult.rows.length === 0) {
      const newUser = await pool.query(
        "INSERT INTO users (uuid, email, password, name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        [uuidv4(), adminEmail, adminPassword, 'Admin User', 'admin']
      );
      
      // Add admin email to whitelist
      await pool.query(
        "INSERT INTO allowed_emails (email, added_by) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
        [adminEmail, newUser.rows[0].id]
      );
      
      console.log("Admin user created successfully");
    }
    
    console.log("Database initialized successfully");
  } catch (error) {
    console.error("Error initializing database:", error);
  }
}

// Initialize database when server starts
initializeDatabase();

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password, rememberMe } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Check if email is whitelisted
    const allowedEmailResult = await pool.query(
      "SELECT * FROM allowed_emails WHERE email = $1", 
      [email]
    );
    
    if (allowedEmailResult.rows.length === 0) {
      return res.status(401).json({ error: 'Your email is not authorized to access this system. Please contact administrator.' });
    }
    
    // Check user credentials
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1", 
      [email]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = userResult.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Set session
    req.session.user = {
      id: user.id,
      uuid: user.uuid,
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    }
    
    res.json({ 
      message: 'Login successful',
      user: req.session.user
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});

// Get current user
app.get('/api/user', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// DELETE endpoint for allowed emails
app.delete('/api/admin/allowed-emails/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      "DELETE FROM allowed_emails WHERE id = $1", 
      [id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    
    res.json({ message: 'Email removed from whitelist' });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get all allowed emails (admin only)
app.get('/api/admin/allowed-emails', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM allowed_emails ORDER BY added_at DESC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Add email to whitelist (admin only)
app.post('/api/admin/allowed-emails', requireAuth, requireAdmin, async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  try {
    const result = await pool.query(
      "INSERT INTO allowed_emails (email, added_by) VALUES ($1, $2) RETURNING id",
      [email, req.session.user.id]
    );
    
    res.status(201).json({ 
      message: 'Email added to whitelist',
      id: result.rows[0].id
    });
  } catch (error) {
    if (error.code === '23505') { // Unique violation
      return res.status(409).json({ error: 'Email already exists in whitelist' });
    }
    console.error("Database error:", error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Serve the login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static files from public directory
app.use(express.static('public'));

// For all other routes, serve the main app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`TicketManager server running on port ${PORT}`);
});