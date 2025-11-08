
// server.js
import express from "express";
import sqlite3 from "sqlite3";
import cors from "cors";
import bcrypt from "bcrypt";

const app = express();
app.use(express.json());
app.use(cors());

// ----- SQLite Database -----
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) console.error(err.message);
  else console.log("Connected to SQLite database.");
});

// ----- Helper -----
const hashPassword = (plain) => bcrypt.hashSync(plain, 10);

// ----- Create Tables & Default Users -----
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT,
  name TEXT,
  type TEXT DEFAULT 'software'
  )`);

  // Add this after opening the database and before inserting users
db.run(`ALTER TABLE users ADD COLUMN type TEXT DEFAULT 'software'`, (err) => {
  if (err) {
    console.log("Column 'type' may already exist:", err.message);
  } else {
    console.log("Column 'type' added to 'users' table.");
  }
});

const stmt = db.prepare(
  "INSERT OR REPLACE INTO users (username, password, role, name, type) VALUES (?, ?, ?, ?, ?)"
);
stmt.run("alice", hashPassword("123"), "employee", "Alice Smith", "software");
stmt.run("admin", hashPassword("admin"), "admin", "John Admin", "software");

stmt.finalize();


  // Work updates table
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

app.post("/api/login", (req, res) => {
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
      // New user → no type yet
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
// app.post("/api/work-update", (req, res) => {
//   const { username, name, userType, date, projectType, projectName, workDone, task, helpTaken, status } = req.body;
//   const timestamp = new Date().toISOString();

//   const stmt = db.prepare(`INSERT INTO work_updates
//     (username, name, userType, date, projectType, projectName, workDone, task, helpTaken, status, timestamp)
//     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

//   stmt.run(username, name, userType, date, projectType, projectName, workDone, task, helpTaken, status, timestamp, function(err) {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json({ success: true, id: this.lastID });
//   });
// });

app.post("/api/work-update", (req, res) => {
  const { username, name, projectType, projectName, workDone, task, helpTaken, status } = req.body;
  const timestamp = new Date().toISOString();

  // Get the user type from users table
  db.get("SELECT type FROM users WHERE username = ?", [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    const userType = row?.type || "software"; // fallback

    const stmt = db.prepare(`INSERT INTO work_updates
      (username, name, userType, date, projectType, projectName, workDone, task, helpTaken, status, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    stmt.run(username, name, userType, req.body.date, projectType, projectName, workDone, task, helpTaken, status, timestamp, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    });
  });
});


// Get all work updates for a user
app.get("/api/work-updates/:username", (req, res) => {
  const username = req.params.username;
  db.all("SELECT * FROM work_updates WHERE username = ? ORDER BY timestamp DESC", [username], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// app.put("/api/set-type/:username", (req, res) => {
//   const { username } = req.params;
//   const { type } = req.body;

//   if (!["software", "hardware"].includes(type)) {
//     return res.status(400).json({ error: "Invalid type" });
//   }

//   db.run(
//     "UPDATE users SET type = ? WHERE username = ?",
//     [type, username],
//     function (err) {
//       if (err) return res.status(500).json({ error: err.message });
//       if (this.changes === 0) return res.status(404).json({ error: "User not found" });

//       res.json({ success: true, type });
//     }
//   );
// });
app.put("/api/set-role/:username", (req, res) => {
  const { username } = req.params;
  const { role } = req.body;

  if (!["admin", "employee"].includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  db.run("UPDATE users SET role = ? WHERE username = ?", [role, username], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: "User not found" });

    res.json({ success: true, role });
  });
});



// server.js
app.delete("/api/work-update/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const stmt = db.prepare("DELETE FROM work_updates WHERE id = ?");
    stmt.run(id, function (err) {
      if (err) return res.status(500).json({ success: false, message: err.message });
      if (this.changes === 0) return res.status(404).json({ success: false, message: "Update not found" });
      res.json({ success: true, message: "Deleted successfully" });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// Admin-only endpoints
app.get("/api/all-work-updates", (req, res) => {
  db.all("SELECT * FROM work_updates ORDER BY timestamp DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get("/api/all-users", (req, res) => {
  db.all("SELECT username, name, role, type FROM users ORDER BY name ASC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Health check
app.get("/.well-known/appspecific/com.chrome.devtools.json", (req, res) => {
  res.json({ status: "ok" });
});

// ----- Start Server -----
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
