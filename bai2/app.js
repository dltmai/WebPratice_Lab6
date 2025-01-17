require("dotenv").config({ path: "../.env" });
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

const app = express();

app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
console.log(process.env.PORT);

const DB_CONFIG = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "jwt_auth",
};

const db = mysql.createConnection(DB_CONFIG);

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to MySQL database.");
});

const query = (sql, values) =>
  new Promise((resolve, reject) => {
    db.query(sql, values, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });

app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userRole = role === "admin" ? "admin" : "user"; // Default to 'user'
    await query(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
      [username, hashedPassword, userRole]
    );
    res
      .status(201)
      .json({ message: "User registered successfully", role: userRole });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error registering user" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const loginAddress = req.ip; // Get user's IP address
  const loginTime = new Date(); // Get current time

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    const users = await query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    const user = users[0];
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Include additional information in JWT
    const tokenPayload = {
      id: user.id,
      username: user.username,
      loginTime,
      loginAddress,
      role: user.role,
    };
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1h" });

    // Save token and additional info to database
    await query(
      "INSERT INTO tokens (user_id, token, login_time, login_address) VALUES (?, ?, ?, ?)",
      [user.id, token, loginTime, loginAddress]
    );

    res.status(200).json({
      message: "Login successful",
      token,
      loginTime,
      loginAddress,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error logging in" });
  }
});

app.get("/verify", async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ message: "Token is required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).json({
      message: "Token is valid",
      decoded,
    });
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
});
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Attach decoded payload to the request
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
}

function isAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied. Admins only." });
  }
  next();
}
app.get("/admin", verifyToken, isAdmin, (req, res) => {
  res.status(200).json({ message: "Welcome, Admin!" });
});

app.post("/logout", async (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ message: "Token is required" });
  }
  try {
    await query("DELETE FROM tokens WHERE token = ?", [token]);
    res.status(200).json({ message: "Logout successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error logging out" });
  }
});
// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
