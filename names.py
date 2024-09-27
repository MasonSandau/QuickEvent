from flask import Flask, render_template, request, redirect, url_for, session, flash
import csv
import os
from datetime import datetime

app = Flask(__name__)

app.secret_key = 'cookie_secret_key_salt_eoiuhgwhouwgeouhi'
CSV_FILE = 'names.csv'
LOG_FILE = 'admin_logs.csv'
LIMITED_USERS_FILE = 'limited_users.csv'

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password'

# Ensure the log file exists before reading
def ensure_log_file_exists():
    if not os.path.exists(LOG_FILE):
        # Create the file and write the header if necessary
        with open(LOG_FILE, 'w', newline='') as logfile:
            writer = csv.writer(logfile)
            writer.writerow(['Timestamp', 'Admin User', 'Action', 'Details'])


# Utility function to log admin actions
def log_admin_action(action, details=""):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    admin_user = session.get('logged_in')

    # Append the log entry to the CSV file
    with open(LOG_FILE, 'a', newline='') as logfile:
        writer = csv.writer(logfile)
        writer.writerow([timestamp, admin_user, action, details])

def is_user_limited(user_name):
    if not os.path.exists(LIMITED_USERS_FILE):
        return False
    with open(LIMITED_USERS_FILE, 'r') as file:
        return user_name in [line.strip() for line in file.readlines()]

def add_limited_user(user_name):
    with open(LIMITED_USERS_FILE, 'a') as file:
        file.write(f'{user_name}\n')

def remove_limited_user(user_name):
    if not os.path.exists(LIMITED_USERS_FILE):
        return
    with open(LIMITED_USERS_FILE, 'r') as file:
        users = file.readlines()
    with open(LIMITED_USERS_FILE, 'w') as file:
        file.writelines([user for user in users if user.strip() != user_name])


@app.route('/admin_debug')
def admin_debug():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    ensure_log_file_exists()  # Make sure log file exists

    logs = []
    try:
        with open(LOG_FILE, 'r') as logfile:
            reader = csv.reader(logfile)
            logs = list(reader)
            if not logs:  # Check if logs are empty
                logs = [['No logs available', '', '', '']]  # Placeholder row
    except Exception as e:
        print(f"Error reading log file: {e}")


    session_data = dict(session)

    return render_template('admin_debug.html', logs=logs, session_data=session_data)



# Landing page
@app.route('/', methods=['GET', 'POST'])
def landing():
    if request.method == 'POST':
        auth_code = request.form['auth_code']
        if auth_code == "salt":
            session['auth_success'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid auth code. Please try again.')
    return render_template('landing.html')


# Home page with form submission
@app.route('/index', methods=['GET', 'POST'])
def index():
    auth_success = session.get('auth_success')
    user_name = request.form.get('user_name')

    if user_name and is_user_limited(user_name):
        return redirect(url_for('already_submitted'))

    if request.method == 'POST' and auth_success:
        name_1 = request.form['name_1']
        name_2 = request.form['name_2']
        name_3 = request.form['name_3']
        date_added = request.form['date_added']

        with open(CSV_FILE, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([date_added, user_name, name_1, name_2, name_3])

        add_limited_user(user_name)

        return redirect(url_for('success', user=user_name))

    return render_template('index.html', auth_success=auth_success)


@app.route('/already_submitted')
def already_submitted():
    return "You've already submitted names. Please contact the admin if this is a mistake."


@app.route('/success/<user>')
def success(user):
    return f'Thank you, {user}, for adding the names!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('view_admin'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            log_admin_action('Login', f'Admin: {username}')
            return redirect(url_for('view_admin'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')


# Admin panel to view, delete, and filter names by date (protected by login)
@app.route('/admin', methods=['GET', 'POST'])
def view_admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    selected_date = None
    data = []
    dates = set()

    with open(CSV_FILE, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            dates.add(row[0])
            data.append(row)

    if request.method == 'POST':
        selected_date = request.form['selected_date']
        data = [row for row in data if row[0] == selected_date]

    return render_template('admin_panel.html', data=data, dates=sorted(dates), selected_date=selected_date)


# Admin page for managing rate-limited users
@app.route('/admin_users', methods=['GET', 'POST'])
def admin_users():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    limited_users = []
    if os.path.exists(LIMITED_USERS_FILE):
        with open(LIMITED_USERS_FILE, 'r') as file:
            limited_users = [user.strip() for user in file.readlines()]

    return render_template('admin_users.html', limited_users=limited_users)


# Route to delete a specific name entry by index
@app.route('/delete_name/<int:row_index>', methods=['POST'])
def delete_name(row_index):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    data = []
    with open(CSV_FILE, 'r') as csvfile:
        reader = csv.reader(csvfile)
        data = list(reader)

    if 0 <= row_index < len(data):
        row = data.pop(row_index)
        log_admin_action('Delete Name', f'User: {row[1]}, Names: {row[2]}, {row[3]}, {row[4]}')

    with open(CSV_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(data)

    return redirect(url_for('view_admin'))


# Delimit user interactions
@app.route('/delimit_user/<string:user_name>', methods=['POST'])
def delimit_user(user_name):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    remove_limited_user(user_name)
    log_admin_action('Delimit User', f'User: {user_name}')
    flash(f'User {user_name} has been delimited.')
    return redirect(url_for('view_admin'))





# Logout function
@app.route('/logout', methods=['POST'])
def logout():
    session['logged_in'] = False
    log_admin_action('Logout', 'Admin logged out')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
