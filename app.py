from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, create_engine
import uuid
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import json
from dotenv import load_dotenv
import os
from psycopg2 import pool
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import secrets

secure_key1 = secrets.token_hex(32)  # Generates a 64-character hexadecimal string
print("Generated Secure Key1:", secure_key1)
hashed_key1 = generate_password_hash(secure_key1)
print("Hashed Key1:", hashed_key1)


secure_key2 = secrets.token_hex(32)  # Generates a 64-character hexadecimal string
print("Generated Secure Key2:", secure_key2)


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECURE_KEY')  # Required for session management

# Database configuration for NeonDB
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")  # Use the NeonDB connection string

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)  # Increased from 80 to 150
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Increased from 20 to 50

class Event(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID as string
    name = db.Column(db.String(150), nullable=False)  # Increased from 100 to 150
    date = db.Column(db.String(20), nullable=False)
    theme = db.Column(db.String(150), nullable=False)  # Increased from 100 to 150
    max_capacity = db.Column(db.Integer, nullable=False)
    names_per_active = db.Column(db.Integer, nullable=False)
    attendees = db.relationship('Attendee', backref='event', lazy=True)

class Attendee(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID as string
    event_id = db.Column(db.String(36), db.ForeignKey('event.id'), nullable=False)
    active_name = db.Column(db.String(150), nullable=False)  # Increased from 100 to 150
    first_name = db.Column(db.String(150), nullable=False)  # Increased from 100 to 150
    last_name = db.Column(db.String(150), nullable=False)  # Increased from 100 to 150
    invite_code = db.Column(db.String(36), unique=True, nullable=False)
    qr_code_generated = db.Column(db.Boolean, default=False)

class regkey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hashed_key = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    used = db.Column(db.Boolean, default=False)

def is_admin():
    return session.get('role') == 'admin'

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    
    if 'username' in session:
        return redirect('dashboard')
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401
    else:
        return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    role = session['role']
    if role == 'admin':
        return redirect(url_for('list_events'))
    elif role == 'active':
        return redirect(url_for('active_dashboard'))  # Redirect to the new active dashboard
    else:
        return "Unauthorized", 403
    

@app.route('/active_dashboard')
def active_dashboard():
    if 'username' not in session or session['role'] != 'active':
        return "Unauthorized", 403

    # Fetch all events
    events = Event.query.all()

    # Fetch attendees invited by the current active user
    active_name = session['username']
    invited_attendees = Attendee.query.filter_by(active_name=active_name).all()

    # Organize attendees by event
    event_attendees = {}
    for attendee in invited_attendees:
        if attendee.event_id not in event_attendees:
            event_attendees[attendee.event_id] = {
                'event_name': Event.query.get(attendee.event_id).name,  # Fetch event name
                'attendees': []
            }
        event_attendees[attendee.event_id]['attendees'].append(attendee)

    return render_template(
        'active.html',
        events=events,
        event_attendees=event_attendees,
        active_name=active_name
    )

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('index'))

@app.route('/create_event', methods=['POST', 'GET'])
def create_event():
    if 'username' not in session or session['role'] != 'admin':
        return "Unauthorized", 403

    if request.method == 'POST': 
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        theme = request.form['theme']
        max_capacity = int(request.form['max_capacity'])
        names_per_active = int(request.form['names_per_active'])

        event_id = str(uuid.uuid4())
        new_event = Event(
            id=event_id,
            name=event_name,
            date=event_date,
            theme=theme,
            max_capacity=max_capacity,
            names_per_active=names_per_active
        )

        db.session.add(new_event)
        db.session.commit()

        return redirect(url_for('list_events'))
    else:
        return render_template('admin.html')

@app.route('/events')
def list_events():
    if 'username' not in session or session['role'] not in ['active', 'admin']:
        return "Unauthorized", 403

    events = Event.query.all()
    return render_template('events.html', events=events, session=session)

@app.route('/event_management/<event_id>')
def event_management(event_id):
    if 'username' not in session or session['role'] not in ['active', 'admin']:
        return "Unauthorized", 403

    event = Event.query.get(event_id)
    if not event:
        return "Event not found", 404

    attendees = Attendee.query.filter_by(event_id=event_id).all()
    num_attendees = len(attendees)

    active_link = f"{request.host_url}invite_attendees/{event_id}"

    return render_template(
        'event_management.html',
        event_id=event_id,
        event=event,
        attendees=attendees,
        active_link=active_link,
        num_attendees=num_attendees
    )

@app.route('/invite_attendees/<event_id>', methods=['GET', 'POST'])
def invite_attendees(event_id):
    if 'username' not in session or session['role'] not in ['active', 'admin']:
        return "Unauthorized", 403

    event = Event.query.get(event_id)
    if not event:
        return "Event not found", 404

    if request.method == 'POST':
        #active_name = request.form['active_name']
        active_name = session['username']
        first_names = request.form.getlist('first_name')
        last_names = request.form.getlist('last_name')

        attendees = Attendee.query.filter_by(event_id=event_id).all()
        if len(attendees) + len(first_names) > event.max_capacity:
            return "Capacity exceeded", 400

        for first_name, last_name in zip(first_names, last_names):
            attendee_id = str(uuid.uuid4())
            invite_code = str(uuid.uuid4())
            new_attendee = Attendee(
                id=attendee_id,
                event_id=event_id,
                active_name=active_name,
                first_name=first_name,
                last_name=last_name,
                invite_code=invite_code
            )
            db.session.add(new_attendee)

        db.session.commit()
        if session['role']=='admin':
            return redirect(url_for('event_management', event_id=event_id))
        else:
            return redirect(url_for('active_dashboard'))

    return render_template('invite_attendees.html', event_id=event_id)

@app.route('/validate_attendee/<invite_code>')
def validate_attendee(invite_code):
    attendee = Attendee.query.filter_by(invite_code=invite_code).first()
    if not attendee:
        return "Attendee not found", 404

    event = Event.query.get(attendee.event_id)
    if not event:
        return "Event not found", 404

    # Get the current time
    validation_time = datetime.now()

    # Extract the timestamp from the QR code data
    qr_data = request.args.get('qr_data')
    if qr_data:
        try:
            qr_data_dict = json.loads(qr_data)
            qr_timestamp_str = qr_data_dict.get('timestamp')
            qr_timestamp = datetime.fromisoformat(qr_timestamp_str)

            # Check if the QR code was scanned within the last 10 minutes
            is_valid = (validation_time - qr_timestamp) <= timedelta(minutes=10)
        except (json.JSONDecodeError, ValueError):
            is_valid = False
    else:
        is_valid = False

    return render_template(
        'validate_attendee.html',
        attendee=attendee,
        event=event,
        is_valid=is_valid,
        validation_time=validation_time.strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/attendee_form/<event_id>/<attendee_id>', methods=['GET', 'POST'])
def attendee_form(event_id, attendee_id):
    attendee = Attendee.query.get(attendee_id)
    if not attendee:
        return "Attendee not found", 404

    if request.method == 'POST':
        attendee.first_name = request.form['first_name']
        attendee.last_name = request.form['last_name']

        # Generate a validation URL with timestamp and invite_code
        validation_url = f"{request.host_url}validate_attendee/{attendee.invite_code}"
        timestamp = datetime.now().isoformat()
        qr_data = {
            'validation_url': validation_url,
            'timestamp': timestamp,
            'invite_code': attendee.invite_code,
            'attendee_name': f"{attendee.first_name} {attendee.last_name}"  # Include attendee name
        }

        # Generate QR code with the validation URL and timestamp
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(json.dumps(qr_data))  # Encode the data as JSON
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')

        # Convert QR code to base64 for embedding in HTML
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        # Update attendee details
        #attendee.qr_code_generated = True
        #db.session.commit()

        return render_template('qr_code.html', qr_code=img_str, attendee_name=f"{attendee.first_name} {attendee.last_name}")

    return render_template('attendee_form.html', event_id=event_id, attendee=attendee)


@app.route('/validate_qr', methods=['POST'])
def validate_qr():
    qr_data = request.json.get('qr_data')
    
    try:
        # Parse the QR code data (assuming it's a JSON string)
        qr_data_dict = json.loads(qr_data)
        invite_code = qr_data_dict.get('invite_code')  # Extract the invite_code
        attendee_name = qr_data_dict.get('attendee_name')  # Extract the attendee's name

        if not invite_code or not attendee_name:
            return jsonify({'status': 'invalid', 'message': 'Invite code or attendee name not found in QR data'}), 400

        # Query the database for the attendee using both invite_code and name
        attendee = Attendee.query.filter_by(invite_code=invite_code).first()
        if not attendee:
            return jsonify({'status': 'invalid', 'message': 'Attendee not found'}), 404

        # Verify the attendee's name matches the one in the QR code
        full_name = f"{attendee.first_name} {attendee.last_name}"

        print("attendee data: " + str(full_name.lower) + " | " + str(attendee_name.lower))
        if full_name.lower() != attendee_name.lower():
            return jsonify({'status': 'invalid', 'message': 'Attendee name does not match'}), 400

        event = Event.query.get(attendee.event_id)
        if not event:
            return jsonify({'status': 'invalid', 'message': 'Event not found'}), 404

        # Check if the QR code was scanned within the last 10 minutes
        #Is valid is mainly for after everything is checked and the time stamps is correct
        #Bad naming and checking el oh el
        qr_timestamp_str = qr_data_dict.get('timestamp')
        qr_timestamp = datetime.fromisoformat(qr_timestamp_str)
        validation_time = datetime.now()
        is_valid = (validation_time - qr_timestamp) <= timedelta(minutes=10)

        return jsonify({
            'status': 'valid' if is_valid else 'invalid',
            'attendee_name': full_name,
            'event_name': event.name,
            'timestamp': validation_time.isoformat(),
            'is_valid': is_valid,
            'stop_scanning': True  # Stop scanning if the QR code is valid
        })

    except json.JSONDecodeError:
        return jsonify({'status': 'invalid', 'message': 'Invalid QR code data format'}), 400
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
        registration_key = request.form.get('registration_key', '')
        role = request.form['role']

        if not username or not password:
            return "Username and password are required", 400

        if len(username) > 150:
            return "Username is too long (maximum 150 characters)", 400

        if len(password) > 255:
            return "Password is too long (maximum 255 characters)", 400

        if len(role) > 50:
            return "Role is too long (maximum 50 characters)", 400

        if User.query.filter_by(username=username).first():
            return "Username already exists", 400

        if role == 'admin':
            reg_key = regkey.query.get(1)  # Assuming you have a single admin key with id=1
            if not reg_key or not check_password_hash(reg_key.hashed_key, registration_key) or reg_key.role != 'admin':
                return "Incorrect or old key", 400

            # Update the used attribute to True
            reg_key.used = True
            db.session.commit()
        elif role == 'active':
            # Check if the registration key is valid
            # need to use check_password_hash not generate hash :(
            reg_key = regkey.query.filter_by(role='active', used=False).all()
            for x in reg_key:
                if check_password_hash(x.hashed_key, registration_key):
                    x.used = True
                    db.session.commit()
                    valid_active_key = True
            #reg_key = regkey.query.filter_by(hashed_key=generate_password_hash(registration_key), role='active', used=False).first()
            if not valid_active_key:
                return "Invalid or used registration key", 400

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        session['username'] = username
        session['role'] = role

        return redirect(url_for('dashboard'))

    return render_template('register.html')


# Route for admins to generate keys
@app.route('/admin/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    if not is_admin():
        return "Unauthorized", 403

    if request.method == 'POST':
        num_keys = int(request.form.get('num_keys', 0))
        if num_keys <= 0:
            flash("Invalid number of keys", "error")
            return redirect(url_for('generate_keys'))

        plaintext_keys = []  # Store plaintext keys temporarily
        for _ in range(num_keys):
            # Generate a random key
            key = secrets.token_urlsafe(16)  # Generates a 16-character secure random string
            plaintext_keys.append(key)

            # Hash and store the key in the database
            hashed_key = generate_password_hash(key)
            new_key = regkey(
                hashed_key=hashed_key,
                role='active',
                used=False
            )
            db.session.add(new_key)
        db.session.commit()

        # Pass the plaintext keys to the template for display
        return render_template('generate_keys.html', plaintext_keys=plaintext_keys)

    return render_template('generate_keys.html', plaintext_keys=None)

@app.route('/admin/view_keys')
def view_keys():
    if not is_admin():
        return "Unauthorized", 403

    # Fetch all unused active keys
    active_keys = regkey.query.filter_by(role='active', used=False).all()
    return render_template('view_keys.html', keys=active_keys)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        admin_key_from_env = os.getenv('ADMIN_KEY')
        if admin_key_from_env:
            reg_key = regkey.query.get(1)
            if not reg_key:
                new_key = regkey(
                    id=1,
                    hashed_key=generate_password_hash(admin_key_from_env),
                    role='admin',
                    used=False,
                )
                db.session.add(new_key)
                db.session.commit()
            else:
                # Update the existing key (if needed)
                reg_key.hashed_key = generate_password_hash(admin_key_from_env)
                db.session.commit()

    app.run(debug=False)