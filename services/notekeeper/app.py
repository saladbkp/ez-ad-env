#!/usr/bin/env python3
"""
NoteKeeper - A deliberately vulnerable service for AD CTF simulation.

Vulnerability: SQL injection in the note search endpoint.
An attacker can extract all notes (including flags) from any user.
"""
import os
import sqlite3
import hashlib
import secrets
import json
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "/data/notekeeper.db")


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.commit()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_current_user(db):
    token = request.headers.get("X-Token", "")
    if not token:
        return None
    cur = db.execute("SELECT * FROM users WHERE token = ?", (token,))
    return cur.fetchone()


@app.route("/api/register", methods=["POST"])
def register():
    db = get_db()
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    token = secrets.token_hex(16)
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)",
            (username, hash_password(password), token),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify({"username": username, "token": token}), 201


@app.route("/api/login", methods=["POST"])
def login():
    db = get_db()
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    cur = db.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, hash_password(password)),
    )
    user = cur.fetchone()
    if not user:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"username": user["username"], "token": user["token"]})


@app.route("/api/notes", methods=["POST"])
def create_note():
    db = get_db()
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "authentication required"}), 401

    data = request.get_json(force=True)
    title = data.get("title", "")
    content = data.get("content", "")
    if not title or not content:
        return jsonify({"error": "title and content required"}), 400

    cur = db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (user["id"], title, content),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "title": title}), 201


@app.route("/api/notes", methods=["GET"])
def list_notes():
    """
    VULNERABLE ENDPOINT - SQL injection via 'search' parameter.
    The search parameter is directly interpolated into the SQL query.
    """
    db = get_db()
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "authentication required"}), 401

    search = request.args.get("search", "")
    if search:
        # VULNERABLE: direct string interpolation allows SQL injection
        query = f"SELECT id, title, content, created_at FROM notes WHERE user_id = {user['id']} AND title LIKE '%{search}%'"
    else:
        query = f"SELECT id, title, content, created_at FROM notes WHERE user_id = {user['id']}"

    try:
        cur = db.execute(query)
        notes = [dict(row) for row in cur.fetchall()]
    except Exception:
        notes = []

    return jsonify(notes)


@app.route("/api/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    db = get_db()
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "authentication required"}), 401

    cur = db.execute(
        "SELECT id, title, content, created_at FROM notes WHERE id = ? AND user_id = ?",
        (note_id, user["id"]),
    )
    note = cur.fetchone()
    if not note:
        return jsonify({"error": "note not found"}), 404
    return jsonify(dict(note))


@app.route("/api/users", methods=["GET"])
def list_users():
    db = get_db()
    cur = db.execute("SELECT id, username FROM users")
    users = [dict(row) for row in cur.fetchall()]
    return jsonify(users)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
