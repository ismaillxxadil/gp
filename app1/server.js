const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = 3000;

app.use(express.json());

const pool = new Pool({
    host: process.env.DB_HOST || "10.10.30.10",
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.POSTGRES_USER || "appuser",
    password: process.env.POSTGRES_PASSWORD || "labpassword",
    database: process.env.POSTGRES_DB || "enterprise_db"
});

app.get("/", (req, res) => {
    res.json({
        service: "Enterprise Application Server",
        server: "APP1",
        status: "running"
    });
});

app.get("/api/health", (req, res) => {
    res.json({
        status: "healthy",
        server: "APP1"
    });
});

app.get("/api/users", (req, res) => {
    res.json({
        users: [
            { id: 1, name: "Alice" },
            { id: 2, name: "Bob" }
        ]
    });
});

// Intentionally vulnerable lab endpoint: do not use this pattern in production.
app.get("/api/users/search", async (req, res) => {
    const name = String(req.query.name || "");
    const query = `SELECT usesysid AS id, usename AS name FROM pg_catalog.pg_user WHERE usename = '${name}'`;

    try {
        const result = await pool.query(query);
        res.json({ users: result.rows });
    } catch (error) {
        console.error("User search failed:", error.message);
        res.status(500).json({ error: "User search failed" });
    }
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Application server listening on port ${PORT}`);
});
