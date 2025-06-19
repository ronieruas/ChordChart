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
        
        cursor.execute("PRAGMA table_info(songs)")
        columns = [column['name'] for column in cursor.fetchall()]
        if 'user_id' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if 'is_public' not in columns:
            cursor.execute("ALTER TABLE songs ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT 0")

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
            
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS setlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                is_public BOOLEAN NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS setlist_songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setlist_id INTEGER NOT NULL,
                song_id INTEGER NOT NULL,
                position INTEGER NOT NULL,
                FOREIGN KEY(setlist_id) REFERENCES setlists(id) ON DELETE CASCADE,
                FOREIGN KEY(song_id) REFERENCES songs(id) ON DELETE CASCADE
            )''')
            
        conn.commit()
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

# --- SONGS API ROUTES ---
@app.route('/api/songs', methods=['GET'])
@login_required
def get_songs_filtered():
    filter_type = request.args.get('filter', 'my_songs')
    db = get_db()
    
    if filter_type == 'public':
        songs_from_db = db.execute('SELECT id, title, original_key FROM songs WHERE is_public = 1').fetchall()
    else:
        songs_from_db = db.execute('SELECT id, title, original_key FROM songs WHERE user_id = ?', (current_user.id,)).fetchall()
    db.close()
    
    songs_list = [dict(song) for song in songs_from_db]

    def normalize_for_sort(text):
        return unicodedata.normalize('NFD', text.lower()).encode('ascii', 'ignore').decode('utf-8')

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

@app.route('/api/songs/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    db = get_db()
    song = db.execute('SELECT content FROM songs WHERE id = ?', (song_id,)).fetchone()
    db.close()
    if song is None: return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

# --- SETLISTS API ROUTES ---
@app.route('/api/setlists', methods=['POST'])
@login_required
def create_setlist():
    data = request.get_json()
    name = data.get('name')
    is_public = data.get('is_public', False)

    if not name or not name.strip():
        return jsonify({"error": "O nome do setlist é obrigatório."}), 400

    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO setlists (name, user_id, is_public) VALUES (?, ?, ?)',
        (name, current_user.id, is_public)
    )
    conn.commit()
    new_setlist_id = cursor.lastrowid
    conn.close()

    return jsonify({"message": "Setlist criado com sucesso!", "setlist": {"id": new_setlist_id, "name": name, "is_public": is_public}}), 201

@app.route('/api/setlists', methods=['GET'])
@login_required
def get_setlists():
    filter_type = request.args.get('filter', 'my_setlists')
    db = get_db()

    if filter_type == 'public':
        setlists_from_db = db.execute('SELECT id, name FROM setlists WHERE is_public = 1 ORDER BY name COLLATE NOCASE ASC').fetchall()
    else: 
        setlists_from_db = db.execute('SELECT id, name FROM setlists WHERE user_id = ? ORDER BY name COLLATE NOCASE ASC', (current_user.id,)).fetchall()
    
    db.close()
    return jsonify([dict(s) for s in setlists_from_db])

@app.route('/api/setlists/<int:setlist_id>', methods=['GET'])
@login_required
def get_setlist_details(setlist_id):
    db = get_db()
    
    setlist = db.execute(
        'SELECT id, name, user_id, is_public FROM setlists WHERE id = ?',
        (setlist_id,)
    ).fetchone()

    if not setlist:
        db.close()
        return jsonify({"error": "Setlist não encontrado."}), 404

    is_owner = setlist['user_id'] == current_user.id
    if not is_owner and not setlist['is_public']:
        db.close()
        return jsonify({"error": "Acesso não autorizado."}), 403

    songs_in_setlist = db.execute(
        '''
        SELECT s.id, s.title, s.original_key
        FROM songs s
        JOIN setlist_songs ss ON s.id = ss.song_id
        WHERE ss.setlist_id = ?
        ORDER BY ss.position ASC
        ''',
        (setlist_id,)
    ).fetchall()
    
    db.close()

    response_data = {
        "id": setlist['id'],
        "name": setlist['name'],
        "is_public": setlist['is_public'],
        "is_owner": is_owner,
        "songs": [dict(song) for song in songs_in_setlist]
    }
    
    return jsonify(response_data)

@app.route('/api/setlists/<int:setlist_id>', methods=['DELETE'])
@login_required
def delete_setlist(setlist_id):
    """Deleta um setlist, mas somente se o usuário for o dono."""
    conn = get_db()
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()

    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404

    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para deletar este setlist."}), 403

    conn.execute('DELETE FROM setlists WHERE id = ?', (setlist_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Setlist deletado com sucesso."})

@app.route('/api/setlists/<int:setlist_id>/songs', methods=['POST'])
@login_required
def add_song_to_setlist(setlist_id):
    """Adiciona uma música a um setlist específico."""
    conn = get_db()

    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    data = request.get_json()
    song_id = data.get('song_id')
    if not song_id:
        conn.close()
        return jsonify({"error": "ID da música é obrigatório."}), 400

    existing = conn.execute(
        'SELECT id FROM setlist_songs WHERE setlist_id = ? AND song_id = ?',
        (setlist_id, song_id)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Esta música já está no setlist."}), 409

    max_pos_result = conn.execute('SELECT MAX(position) FROM setlist_songs WHERE setlist_id = ?', (setlist_id,)).fetchone()
    next_position = (max_pos_result[0] if max_pos_result[0] is not None else -1) + 1

    conn.execute(
        'INSERT INTO setlist_songs (setlist_id, song_id, position) VALUES (?, ?, ?)',
        (setlist_id, song_id, next_position)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Música adicionada ao setlist com sucesso!"}), 201

@app.route('/api/setlists/<int:setlist_id>/songs/<int:song_id>', methods=['DELETE'])
@login_required
def remove_song_from_setlist(setlist_id, song_id):
    """Remove uma música de um setlist específico."""
    conn = get_db()
    
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    conn.execute(
        'DELETE FROM setlist_songs WHERE setlist_id = ? AND song_id = ?',
        (setlist_id, song_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Música removida do setlist com sucesso."})

@app.route('/api/setlists/<int:setlist_id>/songs/order', methods=['PUT'])
@login_required
def update_setlist_order(setlist_id):
    """Atualiza a ordem das músicas em um setlist."""
    conn = get_db()
    
    setlist = conn.execute('SELECT user_id FROM setlists WHERE id = ?', (setlist_id,)).fetchone()
    if not setlist:
        conn.close()
        return jsonify({"error": "Setlist não encontrado."}), 404
    if setlist['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado para modificar este setlist."}), 403

    data = request.get_json()
    song_ids = data.get('song_ids')

    if not isinstance(song_ids, list):
        conn.close()
        return jsonify({"error": "Payload inválido: 'song_ids' deve ser uma lista."}), 400

    try:
        # Usar uma transação para garantir a integridade dos dados
        for index, song_id in enumerate(song_ids):
            conn.execute(
                "UPDATE setlist_songs SET position = ? WHERE setlist_id = ? AND song_id = ?",
                (index, setlist_id, int(song_id))
            )
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": f"Erro no banco de dados: {e}"}), 500
    
    conn.close()
    return jsonify({"message": "Ordem do setlist atualizada com sucesso."})


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)