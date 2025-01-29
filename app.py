from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, current_app, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from dotenv import load_dotenv
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import bcrypt
import os
import threading
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)  # For demonstration purposes only

# Insecure encryption settings
INSECURE_KEY = b"weakkey123456789"  # Hardcoded and short key (16 bytes)
INSECURE_IV = b"weakiv1234567890"  # Hardcoded IV (16 bytes)

# Secure encryption key (dynamically generated per session)
SECURE_KEY = get_random_bytes(32)  # 32-byte key for AES-256

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///grubbug.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    saml_user = db.Column(db.Boolean, default=False)

    # Flask-Login requires these properties/methods
    @property
    def is_active(self):
        # Return True if the user is active; False otherwise
        return True

    @property
    def is_authenticated(self):
        # Return True if the user is authenticated; False otherwise
        return True

    @property
    def is_anonymous(self):
        # Return False because Flask-Login expects this for authenticated users
        return False

    def get_id(self):
        # Return the unique identifier for the user (typically the primary key)
        return str(self.id)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')

class ExamSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(36), unique=True, nullable=False)  # UUID for tracking
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

class ExamChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('exam_session.id'), nullable=False)
    challenge_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Passed, Failed
    score = db.Column(db.Float, nullable=True)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('resources', lazy=True))

with app.app_context():
    db.create_all()
    existing_user = User.query.filter_by(email='alice@example.com').first()
    if not existing_user:
        user1 = User(username='alice', email='alice@example.com', password=generate_password_hash('password123'))
        db.session.add(user1)
    
    existing_user2 = User.query.filter_by(email='bob@example.com').first()
    if not existing_user2:
        user2 = User(username='bob', email='bob@example.com', password=generate_password_hash('password123'))
        db.session.add(user2)

    db.session.commit()

@app.context_processor
def inject_user():
    return dict(user=current_user)

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function for SAML authentication
def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.getenv('SAML_PATH', './saml'))
    return auth

def prepare_flask_request():
    url_data = request.args.to_dict()
    post_data = request.form.to_dict()
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ['SERVER_PORT'],
        'script_name': request.path,
        'get_data': url_data,
        'post_data': post_data,
        'query_string': request.query_string
    }

def get_random_challenge(challenge_id):
    challenges = [
        {"type": "SQL Injection", "prompt": "Bypass this login form..."},
        {"type": "XSS", "prompt": "Inject malicious script to display an alert..."},
        {"type": "CSRF", "prompt": "Submit a forged request..."}
    ]
    return challenges[challenge_id % len(challenges)]

# Define file paths and ownership
FILES = {
    "public_file_1.txt": {"owner": None, "protected": False},
    "public_file_2.txt": {"owner": None, "protected": False},
    "owned_file_1.txt": {"owner": "alice", "protected": False},
    "owned_file_2.txt": {"owner": "bob", "protected": False},
    "protected_file.txt": {"owner": "admin", "protected": True},
}

# Directory for the files
FILE_DIRECTORY = "demo_files"
os.makedirs(FILE_DIRECTORY, exist_ok=True)

def create_or_verify_files():
    """Continuously checks if files exist and recreates them if missing."""
    while True:
        for file_name, file_info in FILES.items():
            file_path = os.path.join(FILE_DIRECTORY, file_name)
            if not os.path.exists(file_path):
                with open(file_path, "w") as f:
                    f.write(f"Owner: {file_info['owner']}\n")
                    f.write(f"Protected: {file_info['protected']}\n")
                    f.write(f"Content: This is a demo file named {file_name}.\n")
        time.sleep(60)  # Check every half second

# Start the background thread
file_thread = threading.Thread(target=create_or_verify_files, daemon=True)
file_thread.start()

# Routes
@app.route('/')
def home():
    menu_items = MenuItem.query.all()
    return render_template('home.html', menu=menu_items)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        # Example: Capture setup configurations from the form
        app_name = request.form.get('app_name')
        admin_email = request.form.get('admin_email')
        # Perform necessary setup tasks
        flash(f'Setup complete for {app_name}. Admin email set to {admin_email}', 'success')
        return redirect(url_for('home'))
    
    return render_template('setup.html')

from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):  # Use check_password_hash
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request()
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/assertion', methods=['POST'])
def saml_assertion():
    req = prepare_flask_request()
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()

    if not errors:
        saml_user_data = auth.get_attributes()
        username = saml_user_data.get('username', [None])[0]
        if username:
            user = User.query.filter_by(username=username, saml_user=True).first()
            if not user:
                user = User(username=username, password='', saml_user=True)
                db.session.add(user)
                db.session.commit()
            login_user(user)
            flash('SAML login successful!', 'success')
            return redirect(url_for('home'))
    flash('SAML login failed.', 'danger')
    return redirect(url_for('login'))

@app.route('/demos', methods=['GET', 'POST'])
def practice():
    if request.method == 'POST':
        return redirect(url_for('home')) 
    return render_template('demos.html')

# Route for A01-2021: Broken Access Control
@app.route('/A01-2021')
def broken_access_control():
    return render_template('A01-2021.html')

# Route for A02-2021: Cryptographic Failures
@app.route('/A02-2021')
def cryptographic_failures():
    return render_template('A02-2021.html')

# Route for A03-2021: Injection
@app.route('/A03-2021')
def injection():
    return render_template('A03-2021.html')

# Route for A04-2021: Insecure Design
@app.route('/A04-2021')
def insecure_design():
    return render_template('A04-2021.html')

# Route for A05-2021: Security Misconfiguration
@app.route('/A05-2021')
def security_misconfiguration():
    return render_template('A05-2021.html')

# Route for A06-2021: Vulnerable and Outdated Components
@app.route('/A06-2021')
def outdated_components():
    return render_template('A06-2021.html')

# Route for A07-2021: Identification and Authentication Failures
@app.route('/A07-2021')
def authentication_failures():
    return render_template('A07-2021.html')

# Route for A08-2021: Software and Data Integrity Failures
@app.route('/A08-2021')
def data_integrity_failures():
    return render_template('A08-2021.html')

# Route for A09-2021: Security Logging and Monitoring Failures
@app.route('/A09-2021')
def logging_failures():
    return render_template('A09-2021.html')

# Route for A10-2021: Server-Side Request Forgery
@app.route('/A10-2021')
def server_side_request_forgery():
    return render_template('A10-2021.html')

# Replace @app.before_first_request logic with this function
def ensure_demo_files():
    """Ensure the demo-files directory exists and is populated."""
    directory = os.path.join(os.path.dirname(__file__), 'demo-files')
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created demo-files directory at {directory}")

    # Ensure the demo files exist
    for file_name, file_info in FILES.items():
        file_path = os.path.join(directory, file_name)
        if not os.path.exists(file_path):
            with open(file_path, "w") as f:
                f.write(f"Owner: {file_info['owner']}\n")
                f.write(f"Protected: {file_info['protected']}\n")
                f.write(f"Content: This is a demo file named {file_name}.\n")
            print(f"Created demo file: {file_name}")

# Call the function when the app context is created
with app.app_context():
    ensure_demo_files()


@app.route('/get-files', methods=['GET'])
def get_files():
    directory = os.path.join(os.path.dirname(__file__), 'demo-files')  # Ensure the correct relative path

    if not os.path.exists(directory):
        print("Directory does not exist.")
        return jsonify({'files': [], 'error': 'Directory does not exist'}), 404

    files = os.listdir(directory)
    return jsonify({'files': files})

@app.route('/exam/start', methods=['GET', 'POST'])
def start_exam():
    if 'user_id' not in session:
        flash('Please log in to start the exam.', 'danger')
        return redirect(url_for('login'))

    # Initialize a new exam session
    session_id = str(uuid.uuid4())  # Unique session identifier
    new_session = ExamSession(user_id=session['user_id'], session_id=session_id)
    db.session.add(new_session)
    db.session.commit()

    # Redirect to the first challenge
    return redirect(url_for('exam_challenge', session_id=session_id, challenge_id=1))

@app.route('/exam/<session_id>/challenge/<int:challenge_id>', methods=['GET', 'POST'])
def exam_challenge(session_id, challenge_id):
    # Fetch session and ensure it's valid
    exam_session = ExamSession.query.filter_by(session_id=session_id).first()
    if not exam_session:
        flash('Invalid exam session.', 'danger')
        return redirect(url_for('home'))

    # Load the current challenge
    challenge = get_random_challenge(challenge_id)  # Function to load randomized challenges

    if request.method == 'POST':
        # Validate the student's submission
        submission = request.form['solution']
        result = validate_challenge(challenge, submission)

        # Update challenge status and score
        exam_challenge = ExamChallenge.query.filter_by(session_id=exam_session.id, id=challenge_id).first()
        exam_challenge.status = 'Passed' if result else 'Failed'
        exam_challenge.score = calculate_score(result)
        db.session.commit()

        # Redirect to the next challenge or finish page
        next_challenge_id = challenge_id + 1
        if next_challenge_id > total_challenges:
            return redirect(url_for('exam_complete', session_id=session_id))
        return redirect(url_for('exam_challenge', session_id=session_id, challenge_id=next_challenge_id))

    return render_template('exam_challenge.html', challenge=challenge)

@app.route('/exam/dashboard')
def exam_dashboard():
    if 'user_id' not in session or not is_instructor(session['user_id']):
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    sessions = ExamSession.query.all()
    return render_template('exam_dashboard.html', sessions=sessions)

@app.route('/order/<int:item_id>', methods=['POST'])
@login_required
def order(item_id):
    user_id = current_user.id
    order = Order(user_id=user_id, item_id=item_id)
    db.session.add(order)
    db.session.commit()

    flash('Order placed successfully!', 'success')
    return redirect(url_for('home'))

from werkzeug.security import generate_password_hash

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already taken.', 'danger')
            return redirect(url_for('signup'))

        # Hash the password and create the user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/admin-panel')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('access-denied'))
    return render_template('admin_panel.html')

app.config['IS_SECURE_MODE'] = True  # Default to secure mode

@app.route('/get-security-mode')
def get_security_mode():
    """Return the current security mode and user login status as JSON."""
    is_secure = app.config['IS_SECURE_MODE']
    user_logged_in = 'user_id' in session  # Check if a user is logged in
    return {"is_secure": is_secure, "user_logged_in": user_logged_in}
    
@app.route('/get-login-status')
def get_login_status():
    """Return whether the user is logged in."""
    return {"logged_in": current_user.is_authenticated}

@app.route('/toggle-security', methods=['POST'])
def toggle_security():
    """Toggle between secure and insecure mode."""
    app.config['IS_SECURE_MODE'] = not app.config['IS_SECURE_MODE']
    current_mode = "Secure" if app.config['IS_SECURE_MODE'] else "Insecure"
    print(f"Security mode toggled. Current mode: {current_mode}")  # Log to console
    return "", 204

@app.route('/privileged-area')
@login_required
def privileged_area():
    """Route for privileged area."""
    if app.config['IS_SECURE_MODE']:
        # Secure mode: check if the user is authorized
        user_role = session.get('role')  # Assume roles are stored in the session
        if user_role != 'admin':  # Only allow access for 'admin' role
            return render_template('access_denied.html', mode="secure")
        # Authorized access
        return render_template('privileged_area.html', mode="secure")
    else:
        # Insecure mode: allow all users to access
        return render_template('privileged_area.html', mode="insecure")

@app.route('/direct-object-reference/<int:resource_id>')
@login_required
def access_resource(resource_id):
    if current_app.config['IS_SECURE_MODE']:
        # Secure Mode: Ensure user is the owner
        resource = Resource.query.filter_by(id=resource_id, owner_id=current_user.id).first()
        if not resource:
            flash("Access denied to this resource.", "danger")
            return redirect(url_for('access_denied', mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure"))

    else:
        # Insecure Mode: Allow access without validation
        resource = Resource.query.filter_by(id=resource_id).first()
        if not resource:
            flash("Resource does not exist.", "danger")
            return redirect(url_for('home'))

    return render_template('resource.html', resource=resource, mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure")

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    if current_app.config['IS_SECURE_MODE']:
        # Secure Mode: Restrict access to the owner's profile
        if current_user.id != user_id:
            flash("Access denied to this profile.", "danger")
            return redirect(url_for('access_denied', mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure"))

    # Insecure Mode: Allow access to any profile
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user, mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure")

@app.route('/approve-transaction/<int:transaction_id>')
@login_required
def approve_transaction(transaction_id):
    if current_app.config['IS_SECURE_MODE']:
        # Secure Mode: Only managers can approve transactions
        if current_user.role != 'manager':
            flash("Access denied: Only managers can approve transactions.", "danger")
            return redirect(url_for('access_denied', mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure"))
    # Insecure Mode: Allow approval by anyone logged in
    transaction = Transaction.query.get_or_404(transaction_id)
    transaction.approved = True
    db.session.commit()
    flash("Transaction approved.", "success")
    return render_template('transaction.html', transaction=transaction, mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure")

@app.route('/api-delete/<int:resource_id>', methods=['DELETE'])
@login_required
def api_delete(resource_id):
    if current_app.config['IS_SECURE_MODE']:
        # Secure Mode: Only allow deletion if the user owns the resource
        resource = Resource.query.filter_by(id=resource_id, owner_id=current_user.id).first()
        if not resource:
            return jsonify({"error": "Unauthorized to delete this resource"}), 403
    else:
        # Insecure Mode: Allow deletion without validation
        resource = Resource.query.filter_by(id=resource_id).first()
        if not resource:
            return jsonify({"error": "Resource not found"}), 404

    db.session.delete(resource)
    db.session.commit()
    return jsonify({"message": "Resource deleted successfully"}), 200

@app.route('/direct-file-access', methods=['GET'])
@login_required
def direct_file_access():
    """Serve a list of files and allow users to access their content."""
    # If no file is specified, render the file listing page
    file_name = request.args.get('file')
    if not file_name:
        return render_template('direct_file_access.html', files=FILES.keys(), mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure")

    # Construct the absolute file path
    file_path = os.path.join(FILE_DIRECTORY, file_name)

    # Ensure the file exists and is within the allowed directory
    if not os.path.isfile(file_path):
        return render_template('access_denied.html', mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure"), 403

    # Check file access based on security mode
    file_info = FILES.get(file_name)
    if not file_info:
        return render_template('access_denied.html', mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure"), 403

    if current_app.config["IS_SECURE_MODE"]:
        # Secure Mode: Check for protected files and ownership
        if file_info["protected"] or (file_info["owner"] and file_info["owner"] != current_user.username):
            return render_template('access_denied.html', mode="secure"), 403

    # Return the file content
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()
        return file_content
    except Exception as e:
        return render_template('access_denied.html', mode="secure" if current_app.config['IS_SECURE_MODE'] else "insecure"), 500

@app.route('/mass-assignment', methods=['POST'])
@login_required
def mass_assignment():
    data = request.get_json()  # Parse JSON payload

    # Determine the current mode
    is_secure_mode = current_app.config['IS_SECURE_MODE']

    # Define the fields to be updated based on mode
    if is_secure_mode:
        allowed_fields = {'username', 'email'}
        updated_data = {field: value for field, value in data.items() if field in allowed_fields}
    else:
        updated_data = data  # Allow all fields in insecure mode

    # Update the user's fields
    for field, value in updated_data.items():
        if hasattr(current_user, field):  # Ensure the field exists
            setattr(current_user, field, value)
    db.session.commit()

    # Only include updated fields in the response
    return jsonify({
        "message": "Profile updated successfully.",
        "updatedFields": {key: getattr(current_user, key) for key in updated_data.keys() if hasattr(current_user, key)},
        "mode": "Secure" if is_secure_mode else "Insecure"
    }), 200

@app.route('/get-profile', methods=['GET'])
@login_required
def get_profile():
    """Return the current user's profile as JSON."""
    return jsonify({
        "username": current_user.username,
        "email": current_user.email,
        "role": getattr(current_user, 'role', 'user')  # Default role is 'user'
    })

@app.route('/idor-login/<int:user_id>')
def idor_login(user_id):
    if current_app.config['IS_SECURE_MODE']:
        # Secure Mode: Prevent logging in as another user
        flash("This action is not allowed.", "danger")
        return redirect(url_for('home'))
    else:
        # Insecure Mode: Allow login as another user
        user = User.query.get(user_id)
        if user:
            login_user(user)
            flash(f"Logged in as {user.username}.", "success")
            return redirect(url_for('dashboard'))
        flash("User not found.", "danger")
        return redirect(url_for('home'))

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    user = current_user
    if current_app.config['IS_SECURE_MODE']:
        # Secure Mode: Allow only specific fields to be updated
        user.email = request.form.get('email')
    else:
        # Insecure Mode: Allow updating all fields
        for key, value in request.form.items():
            setattr(user, key, value)
    db.session.commit()
    flash("Profile updated.", "success")
    return redirect(url_for('profile', user_id=user.id))

@app.route('/access-denied')
def access_denied():
    """Page displayed when access is denied."""
    return render_template('access_denied.html')

@app.route('/api-delete/<string:file_name>', methods=['POST'])
@login_required
def delete_file(file_name):
    """Delete a file if the user has permission."""
    file_path = os.path.join(FILE_DIRECTORY, file_name)

    # Check if the file exists
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found."}), 404

    # Check security mode
    if current_app.config["IS_SECURE_MODE"]:
        file_info = FILES.get(file_name)
        if not file_info:
            return jsonify({"error": "Invalid file."}), 400

        # Secure mode: Check ownership and protection
        if file_info["protected"]:
            return jsonify({"error": "Cannot delete a protected file."}), 403
        if file_info["owner"] and file_info["owner"] != current_user.username:
            return jsonify({"error": "You do not own this file."}), 403

    # Insecure mode: Allow deletion without checks
    os.remove(file_path)
    return jsonify({"message": f"{file_name} deleted successfully."}), 200

@app.route('/direct-file-access')
@login_required
def direct_file_access_test():
    return render_template('direct-file-access.html')

@app.route('/mass-assignment')
@login_required
def mass_assignment_test():
    return render_template('mass_assignment.html')

@app.route('/insecure-encryption', methods=['GET', 'POST'])
@login_required
def insecure_encryption():
    explanation = {
        "secure": "AES-256 encryption with a randomly generated key and IV, ensuring strong security.",
        "insecure": "AES-128 encryption with a weak hardcoded key and IV, making it vulnerable to attacks."
    }
    
    message = None
    encrypted_insecure = None
    encrypted_secure = None
    decrypted_insecure = None
    decrypted_secure = None
    brute_force_time = None

    if request.method == 'POST':
        message = request.form.get("message", "")

        if message:
            # Encrypt with insecure encryption (weak key, predictable IV)
            cipher_insecure = AES.new(INSECURE_KEY, AES.MODE_CBC, INSECURE_IV)
            encrypted_insecure = base64.b64encode(cipher_insecure.encrypt(pad(message.encode(), AES.block_size))).decode()

            # Encrypt with secure encryption (random key and IV)
            secure_iv = get_random_bytes(16)
            cipher_secure = AES.new(SECURE_KEY, AES.MODE_CBC, secure_iv)
            encrypted_secure = base64.b64encode(secure_iv + cipher_secure.encrypt(pad(message.encode(), AES.block_size))).decode()

            # Decrypt in insecure mode (assumes the key is known)
            cipher_insecure_dec = AES.new(INSECURE_KEY, AES.MODE_CBC, INSECURE_IV)
            decrypted_insecure = unpad(cipher_insecure_dec.decrypt(base64.b64decode(encrypted_insecure)), AES.block_size).decode()

            # Decrypt in secure mode
            encrypted_secure_bytes = base64.b64decode(encrypted_secure)
            secure_iv_dec = encrypted_secure_bytes[:16]  # Extract IV
            cipher_secure_dec = AES.new(SECURE_KEY, AES.MODE_CBC, secure_iv_dec)
            decrypted_secure = unpad(cipher_secure_dec.decrypt(encrypted_secure_bytes[16:]), AES.block_size).decode()

            # Estimate brute-force time (assuming 10^9 attempts/sec)
            brute_force_time = f"{(2**56) / 10**9} seconds (approx. 228 years on a fast GPU)" if current_app.config['IS_SECURE_MODE'] else "Instant (Key is hardcoded and known)"

    return render_template(
        'insecure_encryption.html',
        explanation=explanation,
        message=message,
        encrypted_insecure=encrypted_insecure,
        encrypted_secure=encrypted_secure,
        decrypted_insecure=decrypted_insecure,
        decrypted_secure=decrypted_secure,
        brute_force_time=brute_force_time,
        mode="Secure" if current_app.config['IS_SECURE_MODE'] else "Insecure"
    )

def encrypt_message(message, mode):
    if mode == "Insecure":
        cipher = AES.new(INSECURE_KEY, AES.MODE_CBC, INSECURE_IV)
    else:
        cipher = AES.new(SECURE_KEY, AES.MODE_CBC, get_random_bytes(16))  # Secure mode uses dynamic IVs

    padded_message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return base64.b64encode(ciphertext).decode()

def decrypt_message(encrypted_message, mode):
    if mode == "Insecure":
        cipher = AES.new(INSECURE_KEY, AES.MODE_CBC, INSECURE_IV)
    else:
        cipher = AES.new(SECURE_KEY, AES.MODE_CBC, get_random_bytes(16))  # Secure mode would require IV storage

    decrypted_message = unpad(
        cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size
    ).decode()
    return decrypted_message

import hashlib

# Temporary storage (simulating a database)
INSECURE_STORAGE = []
SECURE_STORAGE = []

@app.route('/missing-encryption', methods=['GET', 'POST'])
@login_required
def missing_encryption():
    mode = "Secure" if current_app.config['IS_SECURE_MODE'] else "Insecure"
    intercepted_data = None
    hashed_secure = None

    if request.method == 'POST':
        user_input = request.form.get("data")

        if user_input:
            if current_app.config['IS_SECURE_MODE']:
                # Secure Mode: Hash the data before storing
                hashed_secure = hashlib.sha256(user_input.encode()).hexdigest()
                SECURE_STORAGE.append(hashed_secure)
            else:
                # Insecure Mode: Store the data as plaintext and simulate interception
                INSECURE_STORAGE.append(user_input)
                intercepted_data = user_input  # Simulating an attacker's view

    return render_template(
        'missing_encryption.html',
        mode=mode,
        intercepted_data=intercepted_data,
        hashed_secure=hashed_secure,
        insecure_storage=INSECURE_STORAGE if not current_app.config['IS_SECURE_MODE'] else None,
        secure_storage=SECURE_STORAGE if current_app.config['IS_SECURE_MODE'] else None
    )

# Initialize database and add dummy data
with app.app_context():
    db.create_all()

    if not MenuItem.query.first():
        db.session.add_all([
            MenuItem(name='Margherita Pizza', price=12.99),
            MenuItem(name='Spaghetti Bolognese', price=14.99),
            MenuItem(name='Caesar Salad', price=9.99),
        ])
        db.session.commit()

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
