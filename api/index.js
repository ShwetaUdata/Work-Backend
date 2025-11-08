const express = require("express");
const sqlite3 = require("sqlite3");
const cors = require("cors");
const bcrypt = require("bcrypt");
const serverless = require("serverless-http");

const app = express();
app.use(express.json());
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://work-frontend-ror6.vercel.app"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

// ----- SQLite Database -----
const db = new sqlite3.Database(':memory:');

// ----- Helper -----
const hashPassword = (plain) => bcrypt.hashSync(plain, 10);

// ----- Create Tables & Default Users -----
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT,
    name TEXT,
    type TEXT DEFAULT 'software'
  )`);

  const stmt = db.prepare(
    "INSERT OR REPLACE INTO users (username, password, role, name, type) VALUES (?, ?, ?, ?, ?)"
  );
  stmt.run("alice", hashPassword("123"), "employee", "Alice Smith", "software");
  stmt.run("admin", hashPassword("admin"), "admin", "John Admin", "software");
  stmt.finalize();

  db.run(`CREATE TABLE IF NOT EXISTS work_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    name TEXT,
    userType TEXT,
    date TEXT,
    projectType TEXT,
    projectName TEXT,
    workDone TEXT,
    task TEXT,
    helpTaken TEXT,
    status TEXT,
    timestamp TEXT
  )`);
});

// ----- ROUTES -----

// Root route
app.get("/", (req, res) => {
  res.send("✅ Work Backend is running successfully on Vercel!");
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });

    if (row) {
      bcrypt.compare(password, row.password, (err, match) => {
        if (err) return res.status(500).json({ error: "Error checking password" });
        if (!match) return res.status(401).json({ error: "Invalid credentials" });

        res.json({
          success: true,
          user: row,
          requiresTypeSelection: row.role === "employee" && !row.type
        });
      });
    } else {
      const name = username.charAt(0).toUpperCase() + username.slice(1);
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).json({ error: "Error hashing password" });

        db.run(
          "INSERT INTO users (username, password, role, name, type) VALUES (?, ?, ?, ?, ?)",
          [username, hashedPassword, "employee", name, null],
          function (err) {
            if (err) return res.status(500).json({ error: err.message });

            res.json({
              success: true,
              user: { id: this.lastID, username, role: "employee", name, type: null },
              requiresTypeSelection: true,
            });
          }
        );
      });
    }
  });
});

// Add work update
app.post("/work-update", (req, res) => {
  const { username, name, projectType, projectName, workDone, task, helpTaken, status } = req.body;
  const timestamp = new Date().toISOString();

  db.get("SELECT type FROM users WHERE username = ?", [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    const userType = row?.type || "software";

    const stmt = db.prepare(`INSERT INTO work_updates
      (username, name, userType, date, projectType, projectName, workDone, task, helpTaken, status, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    stmt.run(username, name, userType, req.body.date, projectType, projectName, workDone, task, helpTaken, status, timestamp, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    });
  });
});

// Get work updates by username
app.get("/work-updates/:username", (req, res) => {
  const username = req.params.username;
  db.all("SELECT * FROM work_updates WHERE username = ? ORDER BY timestamp DESC", [username], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Delete update
app.delete("/work-update/:id", (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM work_updates WHERE id = ?", [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, message: "Deleted successfully" });
  });
});

// Admin
app.get("/all-work-updates", (req, res) => {
  db.all("SELECT * FROM work_updates ORDER BY timestamp DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get("/all-users", (req, res) => {
  db.all("SELECT username, name, role, type FROM users ORDER BY name ASC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ----- Export for Vercel -----
module.exports = app;
module.exports.handler = serverless(app);
