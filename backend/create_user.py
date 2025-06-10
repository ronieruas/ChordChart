import sqlite3
import argparse
from werkzeug.security import generate_password_hash

DATABASE = 'songs.db'

def create_user(username, password):
    """Cria um novo usuário no banco de dados com senha criptografada."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Garante que a tabela de usuários exista
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        
        # Cria o hash da senha
        password_hash = generate_password_hash(password)
        
        # Insere o novo usuário
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash))
        
        conn.commit()
        print(f"Usuário '{username}' criado com sucesso!")

    except sqlite3.IntegrityError:
        print(f"Erro: O usuário '{username}' já existe.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Cria um novo usuário para o ChordChart Pro.")
    parser.add_argument("username", type=str, help="O nome de usuário a ser criado.")
    parser.add_argument("password", type=str, help="A senha para o novo usuário.")
    
    args = parser.parse_args()
    
    create_user(args.username, args.password)