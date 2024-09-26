from flask import Flask, render_template, request, redirect, url_for, session, flash
import csv
#import hashlib # to be implimented
#from datetime import datetime

app = Flask(__name__)

app.secret_key = 'cookie_secret_key_salt_eoiuhgwhouwgeouhi'  # Secret key for session management
CSV_FILE = 'names.csv'

# Simple admin credentials (in practice, store this securely using hash stuff...)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password'
auth_code_plain = ''

# Landing page
@app.route('/', methods=['GET', 'POST'])
def landing():
    #if session['auth_success']==True:
    #    return redirect(url_for('index'))
    if request.method == 'POST':
        auth_code = request.form['auth_code']
        #in_auth_hash = hashlib.sha256(auth_code).hexdigest().encode('utf-8').lower_case()
        if auth_code == "salt":  # Check if the auth code is correct
            session['auth_success'] = True  # Set flag for successful authentication
            return redirect(url_for('index'))  # Redirect to the name-adding page
        else:
            flash('Invalid auth code. Please try again.')  # Flash a message for invalid auth code
    return render_template('landing.html')




# Home page with form submission
@app.route('/index', methods=['GET', 'POST'])
def index():
    # Check if the user is authenticated
    auth_success = session.get('auth_success')

    # Check if the user is limited (i.e., already submitted names)
    if session.get('limited', False):
        return redirect(url_for('already_submitted'))

    if request.method == 'POST' and auth_success:
        user_name = request.form['user_name']
        name_1 = request.form['name_1']
        name_2 = request.form['name_2']
        name_3 = request.form['name_3']
        date_added = request.form['date_added']

        # Write to CSV
        with open(CSV_FILE, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([date_added, user_name, name_1, name_2, name_3])

        # Mark the user as limited (prevent them from submitting again)
        session['limited'] = True

        return redirect(url_for('success', user=user_name))

    return render_template('index.html', auth_success=auth_success)


@app.route('/already_submitted')
def already_submitted():
    return "You've already submitted names. Please contact the admin if this is a mistake."


@app.route('/success/<user>')
def success(user):
    return f'Thank you, {user}, for adding the names!'

@app.route('/invalid/<user>')
def invalid(user):
    return f'Sorry {user}, your auth code is not valid.'

@app.route('/limited')
def limited():
    return 'Sorry, it seems either you are not authenticated or you have been limited. Please contact an admin if you belive this is an error'

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('view_admin'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if credentials are correct
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('view_admin'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Admin panel to view, delete, and filter names by date (protected by login)
@app.route('/admin', methods=['GET', 'POST'])
def view_admin():
    if not session.get('logged_in'):  # Check if the admin is logged in
        return redirect(url_for('login'))

    selected_date = None
    data = []
    dates = set()

    # Read the CSV data
    with open(CSV_FILE, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            dates.add(row[0])  # Collect unique dates
            data.append(row)

    if request.method == 'POST':
        selected_date = request.form['selected_date']
        data = [row for row in data if row[0] == selected_date]  # Filter by selected date

    return render_template('admin_panel.html', data=data, dates=sorted(dates), selected_date=selected_date)

@app.route('/admin_users', methods=['GET', 'POST'])
def admin_users():

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    selected_date = None
    data = []
    dates = set()

    # Read the CSV data
    with open(CSV_FILE, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            dates.add(row[0])  # Collect unique dates
            data.append(row)

    return render_template('admin_users.html', data=data, dates=sorted(dates), selected_date=selected_date)




# Route to delete a specific name entry by index
@app.route('/delete_name/<int:row_index>', methods=['POST'])
def delete_name(row_index):
    if not session.get('logged_in'):  # Check if the admin is logged in
        return redirect(url_for('login'))

    data = []

    # Read all rows from CSV
    with open(CSV_FILE, 'r') as csvfile:
        reader = csv.reader(csvfile)
        data = list(reader)

    if 0 <= row_index < len(data):
        data.pop(row_index)  # Remove the row with the specified index

    # Write the updated data back to the CSV
    with open(CSV_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(data)

    return redirect(url_for('view_admin'))



# delimit user interacrations:
@app.route('/delimit_user/<string:user_name>', methods=['POST'])
def delimit_user(user_name):
    if not session.get('logged_in'):  # Check if the admin is logged in
        return redirect(url_for('login'))

    # In a real application, you would keep track of users more persistently (e.g., in a database)
    # Here we assume we reset the "limited" status for the given user
    # Assuming session stores per user can be done differently in a larger system.
    session.pop('limited', None)

    flash(f'User {user_name} has been delimited.')
    return redirect(url_for('view_admin'))




# Logout function
@app.route('/logout', methods=['POST'])
def logout():
    session['logged_in'] = False
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
