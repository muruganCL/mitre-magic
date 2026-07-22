require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');

const { pool } = require('./db');
const { ensureSeeded } = require('./mitre/promptStore');
const authRoutes = require('./routes/auth');
const pageRoutes = require('./routes/pages');
const rulesRoutes = require('./routes/rules');
const adminRoutes = require('./routes/admin');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 },
}));

app.use(authRoutes);
app.use(pageRoutes);
app.use(rulesRoutes);
app.use(adminRoutes);

async function main() {
  const mitreSchema = fs.readFileSync(path.join(__dirname, 'mitre', 'schema.sql'), 'utf8');
  await pool.query(mitreSchema);

  const rulesSchema = fs.readFileSync(path.join(__dirname, 'mitre', 'rules_schema.sql'), 'utf8');
  await pool.query(rulesSchema);

  await ensureSeeded();

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Mitre webapp listening on http://localhost:${PORT}`);
  });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
