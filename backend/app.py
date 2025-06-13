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
login_manager.login_view = 'login'

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
    if user_data:
        return User(id=user_data['id'], username=user_data['username'])
    return None

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys=off")
        cursor.execute("BEGIN TRANSACTION")
        cursor.execute("PRAGMA table_info(songs)")
        columns = [column['name'] for column in cursor.fetchall()]
        if 'original_key' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN original_key TEXT")
        if 'user_id' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if 'is_public' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT 0")

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                content TEXT NOT NULL, original_key TEXT, user_id INTEGER, is_public BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
            )''')
        conn.commit()
        cursor.execute("PRAGMA foreign_keys=on")
        conn.close()

# --- AUTH & USER MANAGEMENT ROUTES ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    db = get_db()
    user_data = db.execute("SELECT * FROM users WHERE username = ?", (data.get('username'),)).fetchone()
    db.close()
    if user_data and check_password_hash(user_data['password_hash'], data.get('password')):
        user = User(id=user_data['id'], username=user_data['username'])
        login_user(user)
        is_admin = user.username == 'admin'
        return jsonify({"message": "Login successful", "user": {"username": user.username, "is_admin": is_admin}})
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        is_admin = current_user.username == 'admin'
        return jsonify({"is_logged_in": True, "user": {"username": current_user.username, "is_admin": is_admin}})
    return jsonify({"is_logged_in": False})

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if current_user.username != 'admin':
        return jsonify({"error": "Acesso não autorizado"}), 403
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Usuário e senha são obrigatórios"}), 400
    password_hash = generate_password_hash(password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        return jsonify({"message": f"Usuário '{username}' criado com sucesso!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"O usuário '{username}' já existe."}), 409
    finally:
        conn.close()

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.username != 'admin':
        return jsonify({"error": "Acesso não autorizado"}), 403
    db = get_db()
    users = db.execute('SELECT id, username FROM users ORDER BY username ASC').fetchall()
    db.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin':
        return jsonify({"error": "Acesso não autorizado"}), 403
    conn = get_db()
    user_to_delete = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_to_delete and user_to_delete['username'] == 'admin':
        conn.close()
        return jsonify({"error": "Não é permitido deletar o usuário administrador"}), 403
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Usuário deletado com sucesso'})

@app.route('/api/users/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    conn = get_db()
    user_data = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if not user_data or not check_password_hash(user_data['password_hash'], data.get('old_password')):
        conn.close()
        return jsonify({"error": "Senha antiga incorreta"}), 401
    new_password_hash = generate_password_hash(data.get('new_password'))
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Senha alterada com sucesso"})

# --- SONGS API ROUTES ---
@app.route('/api/songs', methods=['GET'])
@login_required
def get_songs_filtered():
    filter_type = request.args.get('filter', 'my_songs')
    db = get_db()
    if filter_type == 'public':
        songs = db.execute('SELECT id, title, original_key, user_id FROM songs WHERE is_public = 1 ORDER BY title ASC').fetchall()
    else: 
        songs = db.execute('SELECT id, title, original_key, user_id FROM songs WHERE user_id = ? ORDER BY title ASC', (current_user.id,)).fetchall()
    db.close()
    return jsonify([dict(song) for song in songs])

@app.route('/api/songs', methods=['POST'])
@login_required
def add_song():
    data = request.get_json()
    conn = get_db()
    conn.execute('INSERT INTO songs (title, content, original_key, user_id, is_public) VALUES (?, ?, ?, ?, ?)',
                   (data.get('title'), data.get('content'), data.get('original_key'), current_user.id, data.get('is_public', False)))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música salva com sucesso!"}), 201

@app.route('/api/songs/<int:song_id>', methods=['DELETE'])
@login_required
def delete_song(song_id):
    conn = get_db()
    song = conn.execute("SELECT user_id FROM songs WHERE id = ?", (song_id,)).fetchone()
    if not song or song['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado"}), 403
    conn.execute('DELETE FROM songs WHERE id = ?', (song_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Música deletada com sucesso'})

@app.route('/api/songs/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    db = get_db()
    song = db.execute('SELECT content FROM songs WHERE id = ?', (song_id,)).fetchone()
    db.close()
    if song is None: return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

# (As rotas de Set Lists serão adicionadas na próxima etapa)

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)