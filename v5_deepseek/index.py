from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import uuid
import qrcode
from io import BytesIO
import base64
from datetime import datetime

app = Flask(__name__)
app.config['EVENTS_FOLDER'] = 'events'
app.secret_key = 'supersecretkey'  # Required for session management

# Load or create users.json
USERS_FILE = 'users.json'
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

# Create a default admin user if none exists
def create_default_admin():
    users = load_users()
    if 'admin' not in users:
        users['admin'] = {
            'password': generate_password_hash('adminpass'),
            'role': 'admin'
        }
        save_users(users)

create_default_admin()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    users = load_users()
    user = users.get(username)

    if user and check_password_hash(user['password'], password):
        session['username'] = username
        session['role'] = user['role']
        return redirect(url_for('dashboard'))
    else:
        return "Invalid credentials", 401

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    role = session['role']
    if role == 'admin':
        return render_template('admin.html')
    elif role == 'active':
        return render_template('active.html')
    else:
        return "Unauthorized", 403

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('index'))

@app.route('/create_event', methods=['POST'])
def create_event():
    if 'username' not in session or session['role'] != 'admin':
        return "Unauthorized", 403

    event_name = request.form['event_name']
    event_date = request.form['event_date']
    theme = request.form['theme']
    max_capacity = int(request.form['max_capacity'])
    names_per_active = int(request.form['names_per_active'])

    event_id = str(uuid.uuid4())
    event_folder = os.path.join(app.config['EVENTS_FOLDER'], f"{event_name}-{event_id}")
    os.makedirs(event_folder, exist_ok=True)

    event_data = {
        'event_name': event_name,
        'event_date': event_date,
        'theme': theme,
        'max_capacity': max_capacity,
        'names_per_active': names_per_active,
        'attendees': []
    }

    with open(os.path.join(event_folder, 'event_data.json'), 'w') as f:
        json.dump(event_data, f)

    return redirect(url_for('list_events'))

@app.route('/events')
def list_events():
    if 'username' not in session or session['role'] not in ['active', 'admin']:
        return "Unauthorized", 403

    events = []
    for folder in os.listdir(app.config['EVENTS_FOLDER']):
        event_folder = os.path.join(app.config['EVENTS_FOLDER'], folder)
        event_data_file = os.path.join(event_folder, 'event_data.json')
        if os.path.exists(event_data_file):
            with open(event_data_file, 'r') as f:
                event_data = json.load(f)
                events.append({
                    'event_id': folder.split('-')[-1],  # Extract event ID from folder name
                    'event_name': event_data['event_name'],
                    'event_date': event_data['event_date'],
                    'theme': event_data['theme']
                })

    return render_template('events.html', events=events)

@app.route('/event_management/<event_id>')
def event_management(event_id):
    if 'username' not in session or session['role'] not in ['active', 'admin']:
        return "Unauthorized", 403

    event_folder = find_event_folder(event_id)
    if not event_folder:
        return "Event not found", 404

    with open(os.path.join(event_folder, 'event_data.json'), 'r') as f:
        event_data = json.load(f)

    # Generate the link for actives to add names
    active_link = f"{request.host_url}invite_attendees/{event_id}"

    return render_template('event_management.html', event=event_data, active_link=active_link)

@app.route('/invite_attendees/<event_id>', methods=['GET', 'POST'])
def invite_attendees(event_id):
    if 'username' not in session or session['role'] not in ['active', 'admin']:
        return "Unauthorized", 403

    event_folder = find_event_folder(event_id)
    if not event_folder:
        return "Event not found", 404

    if request.method == 'POST':
        active_name = request.form['active_name']
        first_names = request.form.getlist('first_name')
        last_names = request.form.getlist('last_name')

        with open(os.path.join(event_folder, 'event_data.json'), 'r') as f:
            event_data = json.load(f)

        if len(event_data['attendees']) + len(first_names) > event_data['max_capacity']:
            return "Capacity exceeded", 400

        for first_name, last_name in zip(first_names, last_names):
            attendee_id = str(uuid.uuid4())
            invite_code = str(uuid.uuid4())
            event_data['attendees'].append({
                'attendee_id': attendee_id,
                'active_name': active_name,
                'first_name': first_name,
                'last_name': last_name,
                'invite_code': invite_code,
                'qr_code_generated': False,
                'invite_link': f"/attendee_form/{event_id}/{attendee_id}"  # Ensure event_id is included
            })

        with open(os.path.join(event_folder, 'event_data.json'), 'w') as f:
            json.dump(event_data, f)

        return redirect(url_for('event_management', event_id=event_id))

    return render_template('invite_attendees.html', event_id=event_id)

@app.route('/validate_attendee/<invite_code>')
def validate_attendee(invite_code):
    # Find the attendee with the given invite_code
    for folder in os.listdir(app.config['EVENTS_FOLDER']):
        event_folder = os.path.join(app.config['EVENTS_FOLDER'], folder)
        event_data_file = os.path.join(event_folder, 'event_data.json')
        if os.path.exists(event_data_file):
            with open(event_data_file, 'r') as f:
                event_data = json.load(f)
                attendee = next((a for a in event_data['attendees'] if a['invite_code'] == invite_code), None)
                if attendee:
                    return render_template('validation_result.html', attendee=attendee, event=event_data)

    return "Attendee not found", 404

@app.route('/attendee_form/<event_id>/<attendee_id>', methods=['GET', 'POST'])
def attendee_form(event_id, attendee_id):
    event_folder = find_event_folder(event_id)
    if not event_folder:
        return "Event not found", 404

    with open(os.path.join(event_folder, 'event_data.json'), 'r') as f:
        event_data = json.load(f)

    attendee = next((a for a in event_data['attendees'] if a['attendee_id'] == attendee_id), None)
    if not attendee:
        return "Attendee not found", 404

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        attendee['first_name'] = first_name
        attendee['last_name'] = last_name

        # Generate a validation URL
        validation_url = f"{request.host_url}validate_attendee/{attendee['invite_code']}"

        # Generate QR code with the validation URL
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(validation_url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')

        # Convert QR code to base64 for embedding in HTML
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        attendee['qr_code_generated'] = True
        with open(os.path.join(event_folder, 'event_data.json'), 'w') as f:
            json.dump(event_data, f)

        return render_template('qr_code.html', qr_code=img_str, attendee_name=f"{first_name} {last_name}")

    return render_template('attendee_form.html', event_id=event_id, attendee=attendee)

@app.route('/validate_qr', methods=['POST'])
def validate_qr():
    qr_data = request.json.get('qr_data')

    try:
        qr_data_dict = json.loads(qr_data)
        event_name = qr_data_dict.get('event_name')
        attendee_name = qr_data_dict.get('attendee_name')
        timestamp = qr_data_dict.get('timestamp')
        invite_code = qr_data_dict.get('invite_code')

        # Find the event folder
        event_folder = None
        for folder in os.listdir(app.config['EVENTS_FOLDER']):
            if event_name in folder:
                event_folder = os.path.join(app.config['EVENTS_FOLDER'], folder)
                break

        if not event_folder:
            return jsonify({'status': 'invalid', 'message': 'Event not found'}), 404

        # Load event data
        with open(os.path.join(event_folder, 'event_data.json'), 'r') as f:
            event_data = json.load(f)

        # Find the attendee
        attendee = next((a for a in event_data['attendees'] if a['invite_code'] == invite_code), None)
        if not attendee:
            return jsonify({'status': 'invalid', 'message': 'Attendee not found'}), 404

        # Check if the attendee's name matches
        if attendee.get('first_name') + ' ' + attendee.get('last_name') != attendee_name:
            return jsonify({'status': 'invalid', 'message': 'Name mismatch'}), 400

        return jsonify({
            'status': 'valid',
            'attendee_name': attendee_name,
            'event_name': event_name,
            'timestamp': timestamp
        })

    except Exception as e:
        return jsonify({'status': 'invalid', 'message': str(e)}), 400
    

@app.route('/qr_scanner')
def qr_scanner():
    return render_template('qr_scanner.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if not username or not password:
            return "Username and password are required", 400

        users = load_users()

        if username in users:
            return "Username already exists", 400

        # Save new user
        users[username] = {
            'password': generate_password_hash(password),
            'role': role
        }
        save_users(users)

        # Automatically log in the user after registration
        session['username'] = username
        session['role'] = role

        return redirect(url_for('dashboard'))

    return render_template('register.html')

def find_event_folder(event_id):
    for folder in os.listdir(app.config['EVENTS_FOLDER']):
        if event_id in folder:
            return os.path.join(app.config['EVENTS_FOLDER'], folder)
    return None

if __name__ == "__main__":
   app.run(host="0.0.0.0", port=5000, debug=False)
