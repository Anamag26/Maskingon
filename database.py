import sqlite3
from hashlib import sha256

DB_NAME = "maskingvault.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        name TEXT NOT NULL,
        google_id TEXT
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        pdf_name TEXT NOT NULL,
        masked_count INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    return sha256(password.encode('utf-8')).hexdigest()

def create_user(email: str, password: str, name: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    p_hash = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)", (email, p_hash, name))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_or_create_google_user(email: str, name: str, google_id: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if user:
        conn.close()
        return {"id": user[0], "name": user[1], "email": user[2]}
    else:
        cursor.execute("INSERT INTO users (email, name, google_id) VALUES (?, ?, ?)", (email, name, google_id))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"id": user_id, "name": name, "email": email}

def verify_user(email: str, password: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    p_hash = hash_password(password)
    cursor.execute("SELECT id, name, email FROM users WHERE email = ? AND password_hash = ?", (email, p_hash))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "name": user[1], "email": user[2]}
    return None

def save_history(user_id: int, original_name: str, pdf_name: str, masked_count: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO history (user_id, original_name, pdf_name, masked_count) VALUES (?, ?, ?, ?)",
                   (user_id, original_name, pdf_name, masked_count))
    conn.commit()
    conn.close()

def get_user_history(user_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT original_name, pdf_name, masked_count, created_at FROM history WHERE user_id = ? ORDER BY id DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"original_name": r[0], "pdf_name": r[1], "masked_count": r[2], "created_at": r[3]} for r in rows]