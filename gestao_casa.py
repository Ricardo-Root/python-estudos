import sqlite3

DB_NAME = "gestao_casa.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Tabela de Utilizadores
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'User'
        )
    """)

    # Tabela de Permissões RBAC (Zero Trust)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            user_id INTEGER,
            module TEXT,
            allowed INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, module),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Tabela de Tarefas Dinâmicas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            due_date TEXT,
            assigned_to INTEGER,
            created_by INTEGER,
            visibility TEXT NOT NULL, -- 'PUBLIC' ou 'SHARED'
            shared_with TEXT,          -- IDs separados por vírgula (ex: "2,3")
            status TEXT DEFAULT 'PENDENTE'
        )
    """)

    # Tabela de Mensagens do Chat
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER, -- NULL se for canal GERAL, ou ID do utilizador se for privado
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Garantir que o Super Admin (ID 1) existe
    cursor.execute("INSERT OR IGNORE INTO users (id, username, role) VALUES (1, 'Admin', 'SuperAdmin')")
    
    conn.commit()
    conn.close()

def check_permission(user_id, module):
    if user_id == 1:
        return 1
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT allowed FROM permissions WHERE user_id = ? AND module = ?", (user_id, module))
    res = cursor.fetchone()
    conn.close()
    return res[0] if res else 0

def set_permission(user_id, module, state):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO permissions (user_id, module, allowed)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, module) DO UPDATE SET allowed = ?
    """, (user_id, module, state, state))
    conn.commit()
    conn.close()

def add_user(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username) VALUES (?)", (username,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
