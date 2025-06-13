import os
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
CORS(app, supports_credentials=True)

login_manager = LoginManager()
login_manager.init_app(app)
DATABASE = 'songs.db'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if user_data: return User(id=user_data['id'], username=user_data['username'])
    return None

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                content TEXT NOT NULL, original_key TEXT, user_id INTEGER, is_public BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS set_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                user_id INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS set_list_songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, set_list_id INTEGER NOT NULL,
                song_id INTEGER NOT NULL, song_order INTEGER NOT NULL,
                FOREIGN KEY(set_list_id) REFERENCES set_lists(id) ON DELETE CASCADE,
                FOREIGN KEY(song_id) REFERENCES songs(id) ON DELETE CASCADE
            )''')
        conn.commit()
        conn.close()

# --- AUTH & USER MANAGEMENT ROUTES (Unchanged) ---
# ... (All routes from /api/login to /api/users/change_password are the same)

# --- SONGS API ROUTES (Unchanged) ---
# ... (All routes for /api/songs/... are the same)

# --- SET LIST API ROUTES (NEW) ---
@app.route('/api/setlists', methods=['GET'])
@login_required
def get_set_lists():
    db = get_db()
    lists = db.execute("SELECT id, name FROM set_lists WHERE user_id = ? ORDER BY name ASC", (current_user.id,)).fetchall()
    db.close()
    return jsonify([dict(row) for row in lists])

@app.route('/api/setlists', methods=['POST'])
@login_required
def create_set_list():
    data = request.get_json()
    name = data.get('name')
    if not name: return jsonify({"error": "Nome do Set List é obrigatório"}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO set_lists (name, user_id) VALUES (?, ?)", (name, current_user.id))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return jsonify({"id": new_id, "name": name}), 201

@app.route('/api/setlists/<int:list_id>', methods=['DELETE'])
@login_required
def delete_set_list(list_id):
    conn = get_db()
    # Ensure the user owns this set list
    set_list = conn.execute("SELECT * FROM set_lists WHERE id = ? AND user_id = ?", (list_id, current_user.id)).fetchone()
    if not set_list:
        conn.close()
        return jsonify({"error": "Set List não encontrado ou não autorizado"}), 404
    conn.execute("DELETE FROM set_lists WHERE id = ?", (list_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Set List deletado com sucesso"})
    
@app.route('/api/setlists/<int:list_id>/rename', methods=['PUT'])
@login_required
def rename_set_list(list_id):
    data = request.get_json()
    new_name = data.get('name')
    if not new_name: return jsonify({"error": "Novo nome é obrigatório"}), 400
    conn = get_db()
    conn.execute("UPDATE set_lists SET name = ? WHERE id = ? AND user_id = ?", (new_name, list_id, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({"id": list_id, "name": new_name})

@app.route('/api/setlists/<int:list_id>/songs', methods=['GET'])
@login_required
def get_songs_in_set_list(list_id):
    db = get_db()
    songs = db.execute("""
        SELECT s.id, s.title, sls.song_order
        FROM songs s
        JOIN set_list_songs sls ON s.id = sls.song_id
        WHERE sls.set_list_id = ?
        ORDER BY sls.song_order ASC
    """, (list_id,)).fetchall()
    db.close()
    return jsonify([dict(row) for row in songs])

@app.route('/api/setlists/<int:list_id>/songs', methods=['POST'])
@login_required
def add_song_to_set_list(list_id):
    data = request.get_json()
    song_id = data.get('song_id')
    conn = get_db()
    # Get max order and add 1
    max_order_result = conn.execute("SELECT MAX(song_order) FROM set_list_songs WHERE set_list_id = ?", (list_id,)).fetchone()
    new_order = (max_order_result[0] or 0) + 1
    conn.execute("INSERT INTO set_list_songs (set_list_id, song_id, song_order) VALUES (?, ?, ?)", (list_id, song_id, new_order))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música adicionada ao Set List"}), 201

@app.route('/api/setlists/<int:list_id>/songs/<int:song_id>', methods=['DELETE'])
@login_required
def remove_song_from_set_list(list_id, song_id):
    conn = get_db()
    conn.execute("DELETE FROM set_list_songs WHERE set_list_id = ? AND song_id = ?", (list_id, song_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música removida do Set List"})

# --- All other routes (Auth, User, Songs) are included here for completeness but are unchanged ---
# ...
# ---

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)