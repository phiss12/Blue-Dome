from collections import defaultdict
from datetime import datetime
import sqlite3
import uuid
from flask import Flask, jsonify, render_template, request, redirect, session, Flask, url_for, flash, g, send_file
from werkzeug.datastructures import FileStorage
import pandas as pd
import os
from forms import LoginForm, PasswordResetForm
from database import create_tables, find_user, reset_password
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message, Mail

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config.from_pyfile('config.cfg')  # Assumes you have a mail server configuration in a file named config.cfg
login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

s = URLSafeTimedSerializer('Thisisasecret!')  # Replace 'Thisisasecret!' with your actual secret key

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE id=?", (user_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return User(*row)
        return None

    @staticmethod
    def find_by_username(username):
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, password FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return User(*row)
        return None

def log_user_activity(user_id, username, action, timestamp):
    conn = sqlite3.connect('user_database.db')
    c = conn.cursor()

    c.execute("""
        INSERT INTO user_activities (user_id, username, action, timestamp)
        VALUES (?, ?, ?, ?)
    """, (user_id, username, action, timestamp))

    conn.commit()
    conn.close()


@login_manager.user_loader
def load_user(user_id):
    # Load a user from the session
    return User.get(user_id)


@app.route('/')
def login():
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/login', methods=['POST'])
def process_login():
    session.pop('username', None)
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = find_user(username)
        session['user_id'] = user['user_id']
        session['username'] = user['username']

        if user and check_password_hash(user['password'], password):
            user_id = session['user_id']
            username = session['username'] 
            action = 'Valid login'
            timestamp = datetime.now()
            log_user_activity(user_id, username, action, timestamp)

            conn = sqlite3.connect('user_database.db', check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            login_user(User(user['user_id'], user['username'], user['password']))
            return render_template('index.html', group = result, form=form)
        else:
            user_id = session['user_id']
            username = session['username'] 
            action = 'Invalid login'
            timestamp = datetime.now()
            log_user_activity(user_id, username, action, timestamp)
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    user_id = session['user_id']
    username = session['username'] 
    action = 'User Logged out'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    logout_user()  # Log out the user
    flash('Logged out successfully', 'success')
    return redirect('/')


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        if not user:
            flash('Could not find an account with that email.', 'error')
            return redirect('/reset')
        
        token = s.dumps(email, salt='email-confirm')

        msg = Message('Password reset requested', 
                        sender='noreply@myapp.com', 
                        recipients=[email])

        link = url_for('reset_with_token', token=token, _external=True)

        msg.body = render_template('email/reset.html', link=link)

        mail.send(msg)

        return redirect('/login')
    return render_template('reset.html')

@app.route('/reset/<token>', methods=['POST', 'GET'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h2>The token is expired!</h2>'
    
    if request.method == 'POST':
        password = request.form['password']
        
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()

        hashed_password = generate_password_hash(password)
        cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))

        conn.commit()
        cursor.close()
        conn.close()

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_with_token.html')



@app.route('/reset_password', methods=['POST'])
def reset_password():
    return render_template('reset.html')

@app.route('/reset_password/<token>', methods=['POST'])
def reset_password_with_token(token):
    # Token validation and password reset logic goes here.
    return render_template('reset_with_token.html', token=token)

def send_reset_email(user, token):
    msg = Message('Reset Your Password',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = render_template('email/reset.html', user=user, token=token)
    mail.send(msg)

@app.route('/get_user_data', methods=['POST'])
def get_user_data():
    user_id = session['user_id']
   
    conn = sqlite3.connect('user_database.db')
    c = conn.cursor()

    # Fetch the user's data from the database.
    c.execute("SELECT username, email FROM users WHERE user_id = ?", (user_id,))
    user = c.fetchone()

    conn.close()

    # Make sure we found a user.
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        'username': user[0],
        'email': user[1],
    })

@app.route('/settings')
def settings():
    user_id = session['user_id']
    username = session['username'] 
    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    action = 'On settings page'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    return render_template('settings.html', group = result)  

@app.route('/update_password', methods=['POST'])
def update_password():
    
    username = request.form.get('username')
    email = request.form.get('email')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    if new_password != confirm_new_password:
        user_id = session['user_id']
        username = session['username'] 
        action = 'On settings page - New passwords do not match'
        timestamp = datetime.now()
        log_user_activity(user_id, username, action, timestamp)
        return "New passwords do not match", 400
    
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ? AND email = ?", (username, email))
    row = cursor.fetchone()

    if row is None:
        user_id = session['user_id']
        username = session['username'] 
        action = 'On settings page - User not found when trying to update password'
        timestamp = datetime.now()
        log_user_activity(user_id, username, action, timestamp)
        return "User not found", 404
    else:
        if check_password_hash(row[0], current_password):
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = ? WHERE username = ? AND email = ?", (hashed_password, username, email))
            conn.commit()
            user_id = session['user_id']
            username = session['username'] 
            action = 'On settings page - User has updated password'
            timestamp = datetime.now()
            log_user_activity(user_id, username, action, timestamp)
            return "Password updated successfully", 200
        else:
            user_id = session['user_id']
            username = session['username'] 
            action = 'On settings page - User entered password does not match current'
            timestamp = datetime.now()
            log_user_activity(user_id, username, action, timestamp)
            return "Current password does not match", 401



@app.route('/users')
def users():
    user_id = session['user_id']
    username = session['username'] 
    action = 'On users page'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    # Connect to the database
    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()

    # Fetch all users
    cursor.execute("SELECT user_id, name, username, email, groups FROM users")
    users = cursor.fetchall()

    # Close the connection
    cursor.close()
    conn.close()

    # Render the users template
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['POST'])
def add_user():
    curr_user_id = session['user_id']
    username = session['username'] 
    action = 'On users page - User has added a new user'
    timestamp = datetime.now()
    log_user_activity(curr_user_id, username, action, timestamp)
    # Retrieve the user data from the request
    user_data = request.json

    # Generate a user ID using UUID
    user_id = str(uuid.uuid4())
    
    # Extract the user fields
    name = user_data['name']
    password = user_data['password']
    username = user_data['username']
    email = user_data['email']
    groups = user_data['groups']

    # Connect to the database
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    # Insert the user data into the users table
    cursor.execute("INSERT INTO users (user_id, name, username, password, email, groups) VALUES (?, ?, ?, ?, ?, ?)",
                   (user_id, name, username, generate_password_hash(password), email, groups))
    conn.commit()

    # Close the connection
    cursor.close()
    conn.close()

    # Return a response indicating success
    return jsonify({'message': 'User added successfully', 'user_id': user_id})

@app.route('/excel_uploader')
def excel_uploader():
    user_id = session['user_id']
    username = session['username']
    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close() 
    action = 'On excel uploader page'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    session['current_index'] = 0  # Initialize current index in session
    return render_template('excel_uploader.html', group = result)

@app.route('/edit_user', methods=['POST'])
def edit_user():
    user_id = session['user_id']
    username = session['username'] 
    action = 'On users page - user has editted a user'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    data = request.get_json()
    
    update_fields = []
    for field in ['name', 'username', 'email', 'groups']:
        if field in data:
            update_fields.append(f"{field} = ?")

    update_query = ", ".join(update_fields)

    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute(f"""
        UPDATE users 
        SET {update_query}
        WHERE user_id = ?
        """, tuple(data.get(field) for field in ['name', 'username', 'email', 'groups'] if field in data) + (data.get('user_id'),))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify(message='User updated successfully'), 200


@app.route('/delete_user', methods=['POST'])
def delete_user():
    user_id = session['user_id']
    username = session['username'] 
    action = 'On users page - user has deleted a user'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    data = request.get_json()
    user_id = data.get('user_id')

    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify(message='User deleted successfully'), 200


@app.route('/index')
def home():
    user_id = session['user_id']
    username = session['username'] 
    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    action = 'On home page'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    
    return render_template('index.html', group = result)

@app.route('/generate_reports')
def generate_reports():
    user_id = session['user_id'] 
    # Connect to the SQLite database
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    username = cursor.fetchone()

    user_ids_usernames = conn.execute("SELECT DISTINCT user_id, username FROM user_activities").fetchall()

    # Create a new Excel writer object
    timestamp = datetime.now().date().isoformat()
    versioned_reports = f"{'reports'}_{timestamp}_v{get_latest_version('reports', timestamp, '.xlsx')}{'.xlsx'}"
    reports_path = os.path.join(os.path.dirname(__file__), f'PROCESSED/user_reports/{username[0]}/{timestamp}')
    if not os.path.exists(reports_path):
        os.makedirs(reports_path)
    reports_path = os.path.join(reports_path, versioned_reports)
    writer = pd.ExcelWriter(reports_path , engine='openpyxl')

    # For each user_id and username, query the user_activities table to get the activities for that user,
    # create a DataFrame from the result, and write the DataFrame to a sheet in the Excel file
    for user_id, username in user_ids_usernames:
        activities = conn.execute("SELECT * FROM user_activities WHERE user_id = ?", (user_id,)).fetchall()
        df = pd.DataFrame(activities, columns=['user_id', 'username', 'action', 'timestamp'])
        df.to_excel(writer, sheet_name=f'User {username}', index=False)

    # Save the Excel file
    writer.save()

    # Close the database connection
    conn.close()
  
    return send_file(reports_path, as_attachment=True, download_name='reports.xlsx')


@app.route('/generate_issues')
def generate_issues():
    file_errors_path = session['file_errors_path']
    return send_file(file_errors_path, as_attachment=True, download_name='file_issues.xlsx')


def sort_key(obj):
    if isinstance(obj, FileStorage):
        # Sort FileStorage objects first
        return 0
    else:
        # Sort non-FileStorage objects next
        return 1

@app.route('/process', methods=['POST'])
def process():
    user_id = session['user_id'] 
    # Connect to the SQLite database
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    username = cursor.fetchone()
    files = request.files.getlist('file')
    num_files = len(files)
    headers = []
    file_names = defaultdict(list)
    file_name = []
    timestamp = datetime.now().date().isoformat()
    versioned_reported_issue = f"{'file_errors'}_{timestamp}_v{get_latest_version('file_errors', timestamp, '.xlsx')}{'.xlsx'}"
    file_errors_path = os.path.join(os.path.dirname(__file__), f'PROCESSED/reported_issue/{username[0]}/{timestamp}')
    if not os.path.exists(file_errors_path):
        os.makedirs(file_errors_path)
    file_errors_path = os.path.join(file_errors_path, versioned_reported_issue)
    data = {'File Name': [], 'Issue': []}
    df = pd.DataFrame(data)
    df.to_excel(file_errors_path, index=False)

    for file in sorted(files, key=sort_key):
        # Split the file name and extension
        filename, file_extension = os.path.splitext(file.filename)
        # Modify the file name to include the timestamp or version
        
        versioned_file_name = f"{filename}_{timestamp}_v{get_latest_version(filename, timestamp, file_extension)}{file_extension}"
        file_path = os.path.join(os.path.dirname(__file__), f'PROCESSED/user_excel_uploads/{username[0]}/{timestamp}')
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        file_path = os.path.join(file_path, versioned_file_name)  # Save the file with the modified name
        file.save(file_path)  # Save each uploaded file

        df = pd.read_excel(file_path)
        df = df.fillna(value='ERROR')
        df.to_excel(file_path, index=False)

        # Get the column based on the header name
        file_headers = df.columns.tolist()
        headers.append(file_headers)
        filename = str(filename)
        file_name.append(filename)
        file_names[filename].append(file_path)

    session['file_errors_path'] = file_errors_path
    session['file_names'] = file_names

    username = session['username'] 
    action = 'On execl uploader page - User has uploaded ' + str(file_names) + " files"
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)

    cursor.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('select_headers.html', n=num_files, headers=headers[0], file_names=file_name, group = result)


@app.route('/select_headers', methods = ["POST"])
def select_headers():
    selected_headers = request.form.getlist('header')
    file_names = session['file_names']

    file_paths = []
    row_position = []
    headers = []
    file_name = []
    file_dict = defaultdict(dict)


    for file in file_names:
        df = pd.read_excel(file_names.get(file)[0])
        header_data_dict = defaultdict(list)
        header_index = 0
        for header in selected_headers:
            count = 0
            
        # Get the column based on the header name

            if header in df.columns:
                column = df[header]
            else:
                column = df[df.columns[header_index]]
        # Get the URLs of the images from the column (assuming they are stored as URLs)
            
            for cell in column.tolist():
                header_data_dict[count].append(cell)
                count += 1
            header_index += 1
        
        file_dict[file] = header_data_dict
        headers += [selected_headers] * len(column.tolist())
        row_position.extend(list(range(len(column.tolist()))))
        file_paths += [file_names.get(file)[0]] * len(column.tolist())
        file_name += [file] * len(column.tolist())
    
    session['file_name'] = file_name
    session['file_dict'] = file_dict
    session['file_paths'] = file_paths  # Store file data in session
    session['headers'] = headers
    session['row_position'] = row_position  
    session['current_index'] = 0  # Reset current index in session
    user_id = session['user_id']
    username = session['username'] 
    action = 'On select headers page - User has selected to view ' + str(headers) + " headers of " + str(file_names) + " files"
    timestamp = datetime.now()

    log_user_activity(user_id, username, action, timestamp)
    return redirect('/gallery')

@app.route('/gallery')
def gallery():
    file_paths = session['file_paths']
    file_name = session['file_name']
    file_dict = session['file_dict']
    current_index = session['current_index']
    headers = session['headers']
    row_position = session['row_position']
    user_id = session['user_id']
    username = session['username'] 
    action = 'On gallary page - User is viewing cells of headers they have selected'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)

    conn = sqlite3.connect('user_database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT groups FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('gallery.html', group = result, headers= headers, row_position = row_position, current_index = current_index, file_dict = file_dict, file_name = file_name, file_paths = file_paths)

@app.route('/previous')
def previous():
    user_id = session['user_id']
    username = session['username'] 
    action = 'On gallary page - User has gone back to the previous cell'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    current_index = session['current_index']

    if current_index > 0:
        current_index -= 1
        session['current_index'] = current_index

    return redirect('/gallery')

@app.route('/next')
def next():
    user_id = session['user_id']
    username = session['username'] 
    action = 'On gallary page - User has moved forward to the next cell'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
    file_paths = session['file_paths']
    current_index = session['current_index']

    if current_index < len(file_paths) - 1:
        current_index += 1
        session['current_index'] = current_index

    return redirect('/gallery')

@app.route('/issue', methods=['POST'])
def issue():
    file_errors_path = session['file_errors_path']
    current_index = session['current_index']
    file_name = session['file_name']
    file_dict = session['file_dict']
    row_position = session['row_position']
    for i in file_dict[file_name[current_index]][str(row_position[current_index])]:
        if validate_url(i):
            image_link = i

    
    issue_text = request.form['issue_text']
    file_name = file_name[current_index]
    
    df_existing = pd.read_excel(file_errors_path)

    # Create a new DataFrame with the data you want to add
    data = {'File Name': [file_name], 'Row Posistion': [row_position[current_index] + 1], 'Issue': [issue_text], 'Image': [image_link]}
    df_new = pd.DataFrame(data)
    # Append the new data to the existing DataFrame
    df_combined = pd.concat([df_existing, df_new], ignore_index=True)

    # Save the combined DataFrame to the Excel file
    df_combined.to_excel(file_errors_path, index=False)
    user_id = session['user_id']
    username = session['username'] 
    action = 'On gallary page - User reports a ' + issue_text + ' issue with ' + file_name + ' file'
    timestamp = datetime.now()
    log_user_activity(user_id, username, action, timestamp)
        
    
    return redirect('/gallery')

def validate_url(url):
    if not isinstance(url, str):
        return False
    if url.startswith('http://') or url.startswith('https://'):
        return True
    else:
        return False
    
app.jinja_env.globals.update(validate_url=validate_url)

def get_latest_version(file_name, timestamp, file_extension):
    user_id = session['user_id'] 
    # Connect to the SQLite database
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    username = cursor.fetchone()
    
    base_dir = os.path.dirname(os.path.abspath(__file__))  # Get the script's directory
    file_errors_file_path = os.path.join(base_dir, f'PROCESSED/reported_issue/{username[0]}/{timestamp}')
    if not os.path.exists(file_errors_file_path):
        os.makedirs(file_errors_file_path)
    excel_uploads_file_path = os.path.join(base_dir, f'PROCESSED/user_excel_uploads/{username[0]}/{timestamp}')
    if not os.path.exists(excel_uploads_file_path):
        os.makedirs(excel_uploads_file_path)
    user_reports_file_path = os.path.join(base_dir, f'PROCESSED/user_reports/{username[0]}/{timestamp}')
    if not os.path.exists(user_reports_file_path):
        os.makedirs(user_reports_file_path)

    file_errors_existing_files = []
    user_reports_existing_files = []
    excel_uploads_existing_files = []

    cursor.close()
    conn.close()

    if file_name.startswith("file_errors") and os.path.exists(file_errors_file_path):
        file_errors_existing_files = [f for f in os.listdir(file_errors_file_path) if f.startswith(f"{file_name}_{timestamp}_v")]
    elif file_name.startswith("reports") and os.path.exists(user_reports_file_path):
        user_reports_existing_files = [f for f in os.listdir(user_reports_file_path) if f.startswith(f"{file_name}_{timestamp}_v")]
    elif os.path.exists(excel_uploads_file_path):
        excel_uploads_existing_files = [f for f in os.listdir(excel_uploads_file_path) if f.startswith(f"{file_name}_{timestamp}_v")]
    
    existing_files = file_errors_existing_files + user_reports_existing_files + excel_uploads_existing_files

    if existing_files:
        # Extract the version numbers and find the highest version
        versions = [int(f.split("_v")[-1].split(file_extension)[0]) for f in existing_files]
        latest_version = max(versions)
        return latest_version + 1
    else:
        return 1  # If no existing versions, start with v1


if __name__ == '__main__':
    app.run(debug=True)