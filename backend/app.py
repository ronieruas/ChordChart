import os
import sqlite3
import unicodedata
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
        
        # Add user_id and is_public to songs table if they don't exist
        cursor.execute("PRAGMA table_info(songs)")
        columns = [column['name'] for column in cursor.fetchall()]
        if 'user_id' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if 'is_public' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT 0")

        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                content TEXT NOT NULL, original_key TEXT, user_id INTEGER, is_public BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
            )''')
        conn.commit()
        conn.close()

# --- AUTH & USER MANAGEMENT ROUTES (Unchanged, but included for completeness) ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    db = get_db()
    user_data = db.execute("SELECT * FROM users WHERE username = ?", (data.get('username'),)).fetchone()
    db.close()
    if user_data and check_password_hash(user_data['password_hash'], data.get('password')):
        user = User(id=user_data['id'], username=user_data['username'])
        login_user(user)
        return jsonify({"user": {"username": user.username, "is_admin": user.username == 'admin'}})
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({"is_logged_in": True, "user": {"username": current_user.username, "is_admin": current_user.username == 'admin'}})
    return jsonify({"is_logged_in": False})

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    data = request.get_json()
    password_hash = generate_password_hash(data.get('password'))
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (data.get('username'), password_hash))
        conn.commit()
        return jsonify({"message": f"Usuário '{data.get('username')}' criado com sucesso!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"O usuário '{data.get('username')}' já existe."}), 409
    finally:
        conn.close()

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    db = get_db()
    users = db.execute('SELECT id, username FROM users ORDER BY username ASC').fetchall()
    db.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    conn = get_db()
    user_to_delete = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_to_delete and user_to_delete['username'] == 'admin': return jsonify({"error": "Não é permitido deletar o usuário administrador"}), 403
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
    if not check_password_hash(user_data['password_hash'], data.get('old_password')):
        conn.close()
        return jsonify({"error": "Senha antiga incorreta"}), 401
    new_password_hash = generate_password_hash(data.get('new_password'))
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Senha alterada com sucesso"})

# --- SONGS API ROUTES (UPDATED) ---
@app.route('/api/songs', methods=['GET'])
@login_required
def get_songs_filtered():
    """Busca músicas com base em um filtro e as ordena corretamente em Python."""
    filter_type = request.args.get('filter', 'my_songs')
    db = get_db()
    
    # As consultas SQL agora apenas buscam os dados, sem a cláusula ORDER BY.
    if filter_type == 'public':
        songs_from_db = db.execute('SELECT id, title, original_key FROM songs WHERE is_public = 1').fetchall()
    else: # Padrão para 'my_songs'
        songs_from_db = db.execute('SELECT id, title, original_key FROM songs WHERE user_id = ?', (current_user.id,)).fetchall()
    db.close()
    
    # Converte o resultado para uma lista de dicionários.
    songs_list = [dict(song) for song in songs_from_db]

    # Função para normalizar o texto para ordenação (ignora acentos e caixa).
    def normalize_for_sort(text):
        return unicodedata.normalize('NFD', text.lower()).encode('ascii', 'ignore').decode('utf-8')

    # Ordena a lista de músicas diretamente no Python.
    songs_list.sort(key=lambda song: normalize_for_sort(song['title']))
    
    return jsonify(songs_list)

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
    """Deletes a song, but only if the current user is the owner."""
    conn = get_db()
    song = conn.execute("SELECT user_id FROM songs WHERE id = ?", (song_id,)).fetchone()
    if song is None:
        conn.close()
        return jsonify({"error": "Música não encontrada"}), 404
    if song['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para deletar esta música"}), 403
    
    conn.execute('DELETE FROM songs WHERE id = ?', (song_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Música deletada com sucesso'})

# Get single song remains unchanged
@app.route('/api/songs/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    db = get_db()
    # Any logged in user can view any song if they have the ID, for simplicity.
    # A stricter check could be added here if needed.
    song = db.execute('SELECT content FROM songs WHERE id = ?', (song_id,)).fetchone()
    db.close()
    if song is None: return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)