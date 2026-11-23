import sqlite3
from flask import Flask, request, session, jsonify, render_template_string

app = Flask(__name__)
app.secret_key = "super-secret-dev-key"

DB_NAME = "app_data.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            is_archived INTEGER DEFAULT 0
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (1, 'admin', 'admin123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (2, 'student', 'pass123', 'user')")
    conn.commit()
    conn.close()


# ИСПРАВЛЕНИЕ №1 (ПР №12): Добавлены заголовки безопасности (Security Headers)
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.route("/")
def index():
    return jsonify({"status": "ok", "app": "Task & Notes Manager v1.0"})


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or request.form
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if len(username) < 3 or len(password) < 4:
        return jsonify({"error": "Invalid input length"}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return jsonify({"message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 409
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or request.form
    username = data.get("username")
    password = data.get("password")
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
    ).fetchone()
    conn.close()
    if user:
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"message": "Logged in", "role": user["role"]}), 200
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    if request.method == "POST":
        data = request.get_json() or request.form
        title = data.get("title", "").strip()
        content = data.get("content", "").strip()
        if not title:
            return jsonify({"error": "Title is required"}), 400
        conn.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], title, content),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Note created"}), 201

    rows = conn.execute("SELECT * FROM notes WHERE user_id = ? AND is_archived = 0", (session["user_id"],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200


@app.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    note = conn.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?", (note_id, session["user_id"])).fetchone()
    if not note:
        conn.close()
        return jsonify({"error": "Not found or access denied"}), 404
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"}), 200


@app.route("/notes/search", methods=["GET"])
def search_notes():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    query = request.args.get("q", "")
    conn = get_db()

    # ИСПРАВЛЕНИЕ №2 (ПР №12): Параметризованный запрос вместо конкатенации строк (защита от SQLi)
    rows = conn.execute(
        "SELECT * FROM notes WHERE user_id = ? AND title LIKE ?",
        (session["user_id"], f"%{query}%")
    ).fetchall()

    conn.close()
    return jsonify([dict(r) for r in rows]), 200


@app.route("/render_preview", methods=["GET"])
def render_preview():
    # ИСПРАВЛЕНИЕ №3 (ПР №12): Автоматическое экранирование Jinja2 вместо f-строки (защита от XSS)
    text = request.args.get("text", "Hello")
    return render_template_string("<html><body><h1>Preview: {{ text }}</h1></body></html>", text=text)


@app.route("/admin/users", methods=["GET"])
def admin_users():
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    conn = get_db()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users]), 200


def calculate_discount(price: float, percent: float) -> float:
    if price < 0 or not (0 <= percent <= 100):
        raise ValueError("Invalid arguments")
    return round(price * (1 - percent / 100), 2)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
