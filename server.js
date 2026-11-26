
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY =
    process.env.JWT_SECRET || "change-this-secret-before-deployment";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Створення бази даних
const db = new Database(
    path.join(__dirname, "database.db")
);

db.exec(`
    CREATE TABLE IF NOT EXISTS administrators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
`);

// Створення адміністратора під час першого запуску
const adminExists = db.prepare(
    "SELECT id FROM administrators WHERE username = ?"
).get("admin");

if (!adminExists) {
    const passwordHash = bcrypt.hashSync(
        "Admin12345!",
        12
    );

    db.prepare(`
        INSERT INTO administrators (username, password_hash)
        VALUES (?, ?)
    `).run("admin", passwordHash);

    console.log("Адміністратор створений.");
}

// Авторизація адміністратора
app.post("/api/admin/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            message: "Заповніть усі поля."
        });
    }

    const admin = db.prepare(
        "SELECT * FROM administrators WHERE username = ?"
    ).get(username);

    if (!admin || !bcrypt.compareSync(
        password,
        admin.password_hash
    )) {
        return res.status(401).json({
            message: "Неправильний логін або пароль."
        });
    }

    const token = jwt.sign(
        { id: admin.id, role: "admin" },
        SECRET_KEY,
        { expiresIn: "2h" }
    );

    res.json({
        message: "Авторизація успішна.",
        token
    });
});

// Перевірка прав адміністратора
function checkAdmin(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization) {
        return res.status(401).json({
            message: "Необхідна авторизація."
        });
    }

    const token = authorization.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        if (decoded.role !== "admin") {
            return res.status(403).json({
                message: "Недостатньо прав."
            });
        }

        next();
    } catch {
        return res.status(401).json({
            message: "Недійсний або прострочений токен."
        });
    }
}

// Перевірка адміністративного токена
app.get("/api/admin/check", checkAdmin, (req, res) => {
    res.json({
        message: "Доступ дозволено."
    });
});

app.listen(PORT, () => {
    console.log(`SecureAuth працює: http://localhost:${PORT}`);
});
