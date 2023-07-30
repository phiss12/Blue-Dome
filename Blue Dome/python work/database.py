import sqlite3

DATABASE_NAME = 'user_database.db'

def create_tables():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Create user table if not exists
    # Corrected code
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            groups TEXT NOT NULL
        )
    ''')


    # Create user activities table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activities (
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def find_user(username):
    # Retrieve a user from the database based on the username
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users);")
    columns = cursor.fetchall()
    for column in columns:
        print(column)
    cursor.execute("SELECT id, user_id, name, username, password, email, groups FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        # Convert the user tuple to a dictionary with proper keys
        user_dict = {
            'id': user[0],
            'user_id': user[1],
            'name': user[2],
            'username': user[3],
            'password': user[4],
            'email': user[5],
            'groups': user[6]
        }
        return user_dict
    else:
        return None

def reset_password(username, new_password):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
    conn.commit()

    conn.close()

def save_user_activity(user_id, action):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('INSERT INTO user_activities (user_id, action) VALUES (?, ?)', (user_id, action))
    conn.commit()

    conn.close()
