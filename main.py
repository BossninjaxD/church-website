from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from email.message import EmailMessage
import sqlite3, smtplib, json
from datetime import datetime
from flask_bcrypt import Bcrypt
from functools import wraps
from werkzeug.security import generate_password_hash
from flask_session import Session
from admin_routes import admin_bp
import os


#initaitlize Flask & Bcrypt
main = Flask(__name__)
bcrypt = Bcrypt(main)


# Register admin routes
main.register_blueprint(admin_bp)


# Configure session settings

main.config["SESSION_TYPE"] = "filesystem"
main.config["SESSION_PERMANENT"] = True  # Ensure session persists
main.config["SESSION_USE_SIGNER"] = True
main.config["SESSION_FILE_DIR"] = "flask_sessions"
main.config["SESSION_COOKIE_NAME"] = "church_session"
main.config["SESSION_COOKIE_SECURE"] = False  # Set to True if using HTTPS
main.config["SESSION_COOKIE_HTTPONLY"] = True
main.config["SESSION_COOKIE_SAMESITE"] = "Lax"
main.config["SESSION_REFRESH_EACH_REQUEST"] = True  # Ensures session stays alive

Session(main)  # Initialize Flask-Session


# Load email configurationg from config.json
config_path = os.path.join(os.path.dirname(__file__), "config.json")

with open(config_path, "r") as config_file:
    config = json.load(config_file)

SMTP_SERVER = config["SMTP_SERVER"]
SMTP_PORT = config["SMTP_PORT"]
EMAIL_SENDER = config["EMAIL_SENDER"]
EMAIL_PASSWORD = config["EMAIL_PASSWORD"]
recieve_email_on_form_submit = config["RECIEVE_EMAIL_ON_FORM_SUBMITTION"]

# Secret Key for Sessions (Ensure this is Secure &  Uninue)

main.secret_key = config["SECRET_KEY"]



#Functions
def send_email(subject, recipients, body):
    """Sends an email to multiple recipients while ensuring valid formatting."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER

    # ✅ Ensure recipients is a clean list of valid emails
    if isinstance(recipients, str):
        recipients = [recipients]  # Convert single email to list

    recipients = [email.strip() for email in recipients if email.strip()]  # Remove spaces & empty values
    if not recipients:
        print("⚠️ No valid email recipients found. Skipping email.")
        return  # Exit if no valid emails exist

    msg["To"] = ", ".join(recipients)  # ✅ Join cleaned emails
    msg.set_content(body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"✅ Email sent successfully to: {', '.join(recipients)}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")





# Database connection helper fuction
def get_db_connection():
    conn = sqlite3.connect("church_database.db")
    conn.row_factory = sqlite3.Row 
    return conn

# Authentication & Authorization Helpers
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or session.get('user_role') != role:
                flash("Access Denied. You do not have permission to view this page.", "error")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            flash("Access Denied. You do not have permission to view this page.", "error")
            return redirect(url_for('login')), 403
        return f(*args, **kwargs)
    return decorated_function


def get_settings():
    conn = sqlite3.connect('church_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT feature_name, status FROM settings")
    settings = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return settings

def get_content():
    """Fetches all editable text content from the database."""
    conn = sqlite3.connect('church_database.db')
    conn.row_factory = sqlite3.Row  # Allows dictionary-like row access
    cursor = conn.cursor()

    # Fetch all content
    cursor.execute("SELECT section_name, content FROM content")
    content_data = cursor.fetchall()

    # Convert to dictionary
    content = {row["section_name"]: row["content"] for row in content_data}

    conn.close()
    return content



@main.route('/manage_content', methods=['GET', 'POST'])
def manage_content():
    if 'user_role' not in session or session['user_role'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        section_name = request.form.get('section_name')
        new_content = request.form.get('content')
        cursor.execute("UPDATE content SET content = ? WHERE section_name = ?", (new_content, section_name))
        conn.commit()

    cursor.execute("SELECT * FROM content")
    content_data = cursor.fetchall()
    conn.close()

    return render_template('manage_content.html', content=content_data)



#Admin 
@main.route('/admin')
def admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    urgency_filter = request.args.get('urgency', '')
    message_email_filter = request.args.get('message_email', '')
    sort_by = request.args.get('sort_by', 'submitted_at')

    if message_email_filter:
        cursor.execute("SELECT * FROM messages WHERE email LIKE ? ORDER BY submitted_at DESC;", (f"%{message_email_filter}%",))
    else:
        cursor.execute("SELECT * FROM messages ORDER BY submitted_at DESC;")
    messages = cursor.fetchall()

    if urgency_filter:
        cursor.execute("SELECT * FROM prayer_requests WHERE urgency = ? ORDER BY submitted_at DESC;", (urgency_filter,))
    else:
        cursor.execute("SELECT * FROM prayer_requests ORDER BY submitted_at DESC;")
    prayer_requests = cursor.fetchall()

    cursor.execute(f"SELECT * FROM events ORDER BY {sort_by} DESC;")
    events = cursor.fetchall()

    conn.close()

    return render_template('admin.html', messages=messages, prayer_requests=prayer_requests, events=events)


@main.before_request
def load_settings():
    g.settings = get_settings()  # Load settings globally before every request


@main.route('/debug_session')
def debug_session():
    print("🔍 SESSION DATA:", dict(session))  # Print session data in the terminal
    return jsonify(dict(session))


@main.route('/add_event', methods=['POST'])
@admin_required
def add_event():
    """Allows admins to add new events."""
    event_name = request.form.get('event_name')
    event_date = request.form.get('event_date', 'TBD')
    event_time = request.form.get('event_time', '10:00')  # Expecting HH:MM format
    location = request.form.get('location', 'TBD')
    description = request.form.get('description', '')

    # Convert time to 12-hour AM/PM format
    try:
        formatted_time = datetime.strptime(event_time, "%H:%M").strftime("%I:%M %p")  # Converts to AM/PM
    except ValueError:
        formatted_time = "10:00 AM"  # Default if input is invalid

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO events (event_name, event_date, event_time, location, description)
            VALUES (?, ?, ?, ?, ?)
        """, (event_name, event_date, formatted_time, location, description))
        conn.commit()
        flash("Event added successfully!", "success")

    except sqlite3.OperationalError as e:
        flash(f"Database error: {e}", "error")

    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))




@main.route('/manage_users')
@admin_required
def manage_users():
    """Admin page to view all users and assign staff roles."""
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ Fetch all users (with or without staff roles)
    cursor.execute("SELECT user_id, name, email, role, staff_role FROM users")
    users = cursor.fetchall()

    # ✅ Fetch only staff members (users with a staff role)
    cursor.execute("SELECT user_id, name, email, staff_role FROM users WHERE staff_role IS NOT NULL")
    staff_members = cursor.fetchall()

    conn.close()
    return render_template('manage_users.html', users=users, staff_members=staff_members)


@main.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    """Prevents admin from deleting themselves"""
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account!", "error")
        return redirect(url_for('manage_users'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("User deleted successfully!", "success")
    return redirect(url_for('manage_users'))

@main.route('/reset_session')
def reset_session():
    session.clear()
    return "Session has been reset. Try accessing other pages again."

@main.before_request
def load_logged_in_user():
    """ Ensures session persistence across pages """
    print("🔍 SESSION BEFORE BEFORE_REQUEST:", dict(session))  # Debug session before checking user

    user_id = session.get("user_id")
    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, name, email, role FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        g.user = user
    else:
        g.user = None

    print("✅ SESSION AFTER BEFORE_REQUEST:", dict(session))  # Debug session after checking user


@main.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    """Admin page to edit a user (including optional password reset)."""
    
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        role = request.form.get('role')
        new_password = request.form.get('password')

        # Only update password if a new one is provided
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("""
                UPDATE users SET name = ?, email = ?, role = ?, hashed_password = ? WHERE user_id = ?
            """, (name, email, role, hashed_password, user_id))
        else:
            cursor.execute("""
                UPDATE users SET name = ?, email = ?, role = ? WHERE user_id = ?
            """, (name, email, role, user_id))

        conn.commit()
        conn.close()

        flash("User updated successfully!", "success")
        return redirect(url_for('manage_users'))

    # Fetch user details for editing
    cursor.execute("SELECT user_id, name, email, role FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    return render_template('edit_user.html', user=user)




# Create User Route (Admins Only)
@main.route('/create_user', methods=['POST'])

def create_user():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')  # Defaults to 'user'

    # Securely hash password (decode UTF-8 to store it as text)
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (name, email, hashed_password, role) 
        VALUES (?, ?, ?, ?)
    """, (name, email, hashed_password, role))
    conn.commit()
    conn.close()

    flash(f"User {name} created successfully!", "success")
    return redirect(url_for('manage_users'))




# delete function. this is to delete infomation in the database. 
@main.route('/delete', methods=['GET'])

def delete():
    item_type = request.args.get('type')
    item_id = request.args.get('id')

    if not item_type or not item_id:
        return redirect(url_for('admin'))  # Redirect back to admin if missing params

    conn = get_db_connection()
    cursor = conn.cursor()

    if item_type == "message":
        cursor.execute("DELETE FROM messages WHERE message_id = ?", (item_id,))
    elif item_type == "prayer":
        cursor.execute("DELETE FROM prayer_requests WHERE prayer_id = ?", (item_id,))
    elif item_type == "event":
        cursor.execute("DELETE FROM events WHERE event_id = ?", (item_id,))

    conn.commit()
    conn.close()

    return redirect(url_for('admin'))



# Homepage
@main.route('/')
def home():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all content
    cursor.execute("SELECT section_name, content FROM content")
    content_data = cursor.fetchall()
    
    # Fetch all settings
    cursor.execute("SELECT feature_name, status FROM settings")
    settings_data = cursor.fetchall()
    
    # Convert query results to dictionaries
    content = {row["section_name"]: row["content"] for row in content_data}
    settings = {row["feature_name"]: row["status"] for row in settings_data}
    
    conn.close()
    
    return render_template('index.html', content=content, settings=settings)



# General Pages
@main.route('/about')
def about():
    try:
        settings = get_settings()  # Fetch settings
        content = get_content()  # Fetch editable text content

        if settings.get("enable_about") == "disabled":
            return redirect(url_for('home'))

        return render_template('about.html', settings=settings, content=content)

    except Exception as e:
        print(f"Error loading About page: {e}")
        flash("There was an issue loading the page. Please try again later.", "error")
        return redirect(url_for('home'))




@main.route('/ministries')
def ministries():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch settings
    settings = get_settings()

    # Fetch content
    cursor.execute("SELECT section_name, content FROM content")
    content_data = cursor.fetchall()
    content = {row["section_name"]: row["content"] for row in content_data}
    
    conn.close()
    
    return render_template('ministries.html', settings=settings, content=content)


@main.route('/watch')
def watch():
    settings = get_settings()
    if settings.get("enable_watch") == "disabled":
        return redirect(url_for('home'))
    return render_template('watch.html', settings=settings)

from flask import render_template, request, redirect, url_for, flash
from datetime import datetime

@main.route('/events', methods=['GET', 'POST'])
def events():
    """Displays all upcoming church events and handles event suggestions/RSVPs."""
    settings = get_settings()  
    if settings.get("enable_events") == "disabled":
        return redirect(url_for('home')) #redirect to home if disabled
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all upcoming events, ordered by soonest date
    cursor.execute("""
        SELECT event_id, event_name, event_date, event_time, location, description
        FROM events
        WHERE event_date >= DATE('now')  -- Only future events
        ORDER BY event_date ASC
    """)
    events = cursor.fetchall()

    formatted_events = []
    for event in events:
        event_dict = dict(event)  # Convert SQLite Row object to dictionary
        event_time = event_dict.get("event_time", "").strip()
        event_date = event_dict["event_date"]

        # Default to "TBD"
        formatted_time = "TBD"
        google_calendar_time = ""

        if event_time and event_time.lower() != "tbd":
            try:
                # Handle both `10:00 AM` and `18:00` formats
                if "AM" in event_time or "PM" in event_time:
                    # Already formatted as AM/PM
                    formatted_time = event_time
                    hours, minutes = map(int, event_time[:-3].split(":"))
                    am_pm = event_time[-2:]
                    if am_pm == "PM" and hours != 12:
                        hours += 12
                    elif am_pm == "AM" and hours == 12:
                        hours = 0
                else:
                    # Convert 24-hour format to AM/PM
                    hours, minutes = map(int, event_time.split(":"))
                    am_pm = "AM" if hours < 12 else "PM"
                    formatted_hours = hours if 1 <= hours <= 12 else (hours - 12 if hours > 12 else 12)
                    formatted_time = f"{formatted_hours}:{minutes:02d} {am_pm}"

                # Format time for Google Calendar
                formatted_date = event_date.replace("-", "")  # Convert YYYY-MM-DD to YYYYMMDD
                calendar_time = f"{hours:02d}{minutes:02d}00"
                google_calendar_time = f"{formatted_date}T{calendar_time}/{formatted_date}T{calendar_time}"
            
            except ValueError:
                formatted_time = "TBD"  # Handle errors gracefully

        else:
            # Mark as an **All-Day Event**
            formatted_date = event_date.replace("-", "")
            google_calendar_time = f"{formatted_date}/{formatted_date}"

        # Update dictionary for rendering
        event_dict["event_time"] = formatted_time
        event_dict["google_calendar_time"] = google_calendar_time

        formatted_events.append(event_dict)

    conn.close()
    return render_template('events.html', events=formatted_events, settings=settings)









@main.route('/give', methods=['GET', 'POST'])
def give():
    settings = get_settings()
    if settings.get("enable_give") == "disabled":
        return redirect(url_for('home'))

    if request.method == 'POST':
        amount = request.form.get('amount') or request.form.get('custom_amount')
        donation_type = request.form.get('donation_type')
        frequency = request.form.get('recurring_frequency') if donation_type == "recurring" else "One-Time"
        payment_method = request.form.get('payment')

        print(f"New Donation: ${amount} - {donation_type} ({frequency}) via {payment_method}")

        return render_template('give.html', success=True)

    return render_template('give.html', success=False, settings=settings)


@main.route('/contact', methods=['GET', 'POST'])
def contact():
    settings = get_settings()
    
    # Redirect if the page is disabled
    if settings.get("enable_contact") == "disabled":
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch content for editable text
    cursor.execute("SELECT section_name, content FROM content")
    content_data = cursor.fetchall()
    content = {row["section_name"]: row["content"] for row in content_data}
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Format: YYYY-MM-DD HH:MM:SS

        # Save message to the database
        cursor.execute("INSERT INTO messages (name, email, message, submitted_at) VALUES (?, ?, ?, ?)", 
                       (name, email, message, submitted_at))
        conn.commit()
        conn.close()

        # Email subject & body
        subject = "New Contact Form Submission"
        email_body = f"""
        New message received from the contact form:

        Name: {name}
        Email: {email}
        Message: {message}
        Submitted At: {submitted_at}
        """

        # Send email notification if enabled
        if recieve_email_on_form_submit: 
            send_email(subject, EMAIL_SENDER, email_body)
        
        return render_template('contact.html', success=True, settings=settings, content=content)

    conn.close()
    return render_template('contact.html', settings=settings, content=content)




# Add secret key for session management
main.secret_key =   config["SECRET_KEY"] # secret secure key

# Logout Route
@main.route('/logout')
def logout():
    """Logs out the user by clearing the session and redirecting to login page."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# Persistent User Session

@main.before_request
def load_logged_in_user():
    """ Ensures session persistence across pages """
    user_id = session.get("user_id")
    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, name, email, role FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        g.user = user
    else:
        g.user = None



@main.route('/test')
def test_route():
    return "Flask is working!"

# Login Route
@main.route('/login', methods=['GET', 'POST'])
def login():

    settings = get_settings()

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        # Debugging: Ensure user data is retrieved correctly
        if user is None:
            print(f"❌ DEBUG: User with email {email} not found in database.")
            flash("User not found. Please check your email.", "error")
            return redirect(url_for('login'))

        # Debugging: Print retrieved user data (excluding password for security)
        print(f"🔍 DEBUG: Found User - ID: {user['user_id']}, Email: {user['email']}, Role: {user['role']}")

        # Debugging: Print entered password and stored hash for verification
        stored_hashed_password = user["hashed_password"]
        print(f"🔍 DEBUG: Hashed Password in DB: {stored_hashed_password}")
        print(f"🔍 DEBUG: Entered Password: {password}")

        # Verify Password
        if bcrypt.check_password_hash(stored_hashed_password, password):
            print("✅ DEBUG: Password match successful!")

            session.clear()  # Clear session AFTER confirming password to avoid wiping it too early

            # Store session values properly
            session['user_id'] = user["user_id"]
            session['user_email'] = user["email"]
            session['user_role'] = user["role"]
            session.permanent = True  # Ensure session persists
            session.modified = True  # Ensure Flask saves session changes

            print("✅ SESSION AFTER LOGIN:", dict(session))  # Debugging session after setting values

            flash("Login successful!", "success")
            return redirect(url_for('admin')) if user["role"] == "admin" else redirect(url_for('user_dashboard', user_id=user["user_id"]))

        else:
            print("❌ DEBUG: Password does NOT match!")
            flash("Invalid credentials. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html', settings=settings)

@main.route('/customize_content', methods=['GET', 'POST'])
def customize_content():
    settings = get_settings()
    content = get_content()

    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid request"}), 400

            conn = sqlite3.connect('church_database.db')
            cursor = conn.cursor()

            for section_name, new_text in data.items():
                cursor.execute("UPDATE content SET content = ? WHERE section_name = ?", (new_text, section_name))

            conn.commit()
            conn.close()
            
            return jsonify({"success": True, "message": "Content updated successfully"})

        except Exception as e:
            print(f"Error updating content: {e}")
            return jsonify({"error": "Database error"}), 500

    return render_template("customize_content.html", settings=settings, content=content)


@main.route('/delete_prayer', methods=['POST'])
def delete_prayer():
    """Handles deletion of a prayer request."""

    if 'user_id' not in session:
        flash("You need to be logged in to delete a prayer request.", "error")
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Get the prayer ID from the form submission
    prayer_id = request.form.get('prayer_id')

    if not prayer_id:
        flash("Invalid prayer request ID.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # ✅ First, fetch the user's email
    cursor.execute("SELECT email FROM users WHERE user_id = ?", (user_id,))
    user_data = cursor.fetchone()

    if not user_data:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    user_email = user_data["email"]  # Extract user email

    # ✅ Now delete the prayer if it belongs to the user via email or user_id
    cursor.execute("""
        DELETE FROM prayer_requests 
        WHERE prayer_id = ? AND (user_id = ? OR email = ?)
    """, (prayer_id, user_id, user_email))

    if cursor.rowcount == 0:
        conn.close()
        flash("Prayer request not found or unauthorized.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    conn.commit()
    conn.close()

    flash("Prayer request deleted successfully.", "success")
    return redirect(url_for('user_dashboard', user_id=user_id))

@main.route('/user_dashboard/<int:user_id>')
def user_dashboard(user_id):
    """Displays the user dashboard with financial giving records, prayer requests, and unread messages."""

    # ✅ Ensure the user is logged in and authorized
    if 'user_id' not in session or session['user_id'] != user_id:
        flash("Access denied. You cannot view this page.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # ✅ Fetch user info, including email
    cursor.execute("""
        SELECT u.name, u.email, u.role, 
               COALESCE(SUM(f.amount), 0) AS total_donations, 
               COUNT(f.amount) AS donation_count
        FROM users u
        LEFT JOIN financial_records f ON u.user_id = f.user_id
        WHERE u.user_id = ?
        GROUP BY u.user_id
    """, (user_id,))
    user_data = cursor.fetchone()

    if not user_data:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for('login'))

    user_email = user_data["email"]  # Extract user email

    # ✅ Fetch all prayers associated with this email (not just `user_id`)
    cursor.execute("""
        SELECT prayer_id, prayer_request, submitted_at, read_status 
        FROM prayer_requests 
        WHERE email = ? 
        ORDER BY submitted_at DESC
    """, (user_email,))
    prayers = cursor.fetchall()

    print("DEBUG: Prayers fetched from DB:", [dict(p) for p in prayers])  # Debugging log

    # ✅ Count total prayers (from all sources)
    total_prayers = len(prayers)

    # ✅ Count unread prayers correctly
    unread_prayers = sum(1 for p in prayers if p["read_status"] == 0)

    print(f"DEBUG: Total Prayers Counted: {total_prayers}")
    print(f"DEBUG: Unread Prayers Counted: {unread_prayers}")

    conn.close()

    return render_template(
        'user_dashboard.html', 
        user=user_data, 
        prayers=prayers,
        unread_prayers=unread_prayers,
        total_prayers=total_prayers
    )



@main.route('/archive_message', methods=['POST'])
def archive_message():
    """Marks a contact message as archived instead of deleting it."""
    
    if 'user_id' not in session or session.get("user_role") != "admin":
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = request.get_json()
    message_id = data.get("message_id")

    if not message_id:
        return jsonify({"success": False, "error": "Invalid message ID"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Debugging: Check if the message exists
    cursor.execute("SELECT message_id, archived FROM messages WHERE message_id = ?", (message_id,))
    message_before = cursor.fetchone()

    if not message_before:
        conn.close()
        return jsonify({"success": False, "error": "Message not found"}), 404

    print("MESSAGE BEFORE UPDATE:", dict(message_before))

    # Archive the message
    cursor.execute("UPDATE messages SET archived = 1 WHERE message_id = ?", (message_id,))
    conn.commit()

    # Debugging: Confirm the update was applied
    cursor.execute("SELECT message_id, archived FROM messages WHERE message_id = ?", (message_id,))
    message_after = cursor.fetchone()
    conn.close()

    if message_after["archived"] == 1:
        print("✅ MESSAGE ARCHIVED SUCCESSFULLY:", dict(message_after))
    else:
        print("❌ ERROR: MESSAGE NOT ARCHIVED!")

    return jsonify({"success": True})










@main.route('/archive_prayer', methods=['POST'])
def archive_prayer():
    """Marks a prayer request as archived instead of deleting it."""

    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized action."}), 403

    user_id = session['user_id']
    user_role = session.get('user_role')
    
    data = request.json  # Handle JSON requests
    prayer_id = data.get('prayer_id')

    if not prayer_id:
        return jsonify({"error": "Invalid prayer request."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    if user_role == "admin":
        # ✅ Admins can archive any prayer request
        cursor.execute("UPDATE prayer_requests SET archived = 1 WHERE prayer_id = ?", (prayer_id,))
    else:
        # ✅ Regular users can only archive their own prayers
        cursor.execute("SELECT * FROM prayer_requests WHERE prayer_id = ? AND user_id = ?", (prayer_id, user_id))
        prayer = cursor.fetchone()

        if not prayer:
            conn.close()
            return jsonify({"error": "Prayer request not found or does not belong to you."}), 403
        
        cursor.execute("UPDATE prayer_requests SET archived = 1 WHERE prayer_id = ?", (prayer_id,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})



@main.route('/mark_read/<string:item_type>', methods=['POST'])
def mark_read(item_type):
    """Marks a message or prayer request as read."""

    # Check if user is logged in and is an admin
    if 'user_id' not in session or session.get("user_role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403  # Fix: Uses correct session key

    data = request.json
    item_id = data.get("id")

    if not item_id:
        return jsonify({"error": "Invalid item ID"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    if item_type == "message":
        cursor.execute("UPDATE messages SET read_status = 1 WHERE message_id = ?", (item_id,))
    elif item_type == "prayer":
        cursor.execute("UPDATE prayer_requests SET read_status = 1 WHERE prayer_id = ?", (item_id,))
    else:
        conn.close()
        return jsonify({"error": "Invalid item type"}), 400

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@main.route('/get_unread_counts')
def get_unread_counts():
    """Returns the latest unread messages and prayer request counts."""
    
    if 'user_id' not in session or session.get("user_role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM messages WHERE read_status = 0")
    unread_messages = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM prayer_requests WHERE read_status = 0")
    unread_prayers = cursor.fetchone()[0]

    conn.close()

    return jsonify({"unread_messages": unread_messages, "unread_prayers": unread_prayers})



@main.route('/mark_prayer_read', methods=['POST'])
def mark_prayer_read():
    """Marks a prayer request as read."""

    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session['user_id']
    prayer_id = request.json.get('prayer_id')

    if not prayer_id:
        return jsonify({"error": "Invalid prayer request"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ Check if the prayer request belongs to the user
    cursor.execute("SELECT * FROM prayer_requests WHERE prayer_id = ? AND user_id = ?", (prayer_id, user_id))
    prayer = cursor.fetchone()

    if not prayer:
        conn.close()
        return jsonify({"error": "Prayer request not found or does not belong to you"}), 404

    # ✅ Update read_status to 1 (mark as read)
    cursor.execute("UPDATE prayer_requests SET read_status = 1 WHERE prayer_id = ? AND user_id = ?", (prayer_id, user_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True})





# Register Route
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # ✅ Ensure passwords match
        if password != confirm_password:
            flash("Passwords do not match. Try again.", "error")
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ Check if the email is already registered
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already registered. Try logging in.", "error")
            conn.close()
            return redirect(url_for('register'))

        # ✅ Hash the password before storing
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # ✅ Insert user into database
        cursor.execute("""
            INSERT INTO users (name, email, hashed_password, role) 
            VALUES (?, ?, ?, ?)
        """, (name, email, hashed_password, 'user'))

        conn.commit()

        # ✅ Fetch the newly inserted user ID
        cursor.execute("SELECT user_id FROM users WHERE email = ?", (email,))
        new_user = cursor.fetchone()
        conn.close()

        # ✅ Automatically log in the new user
        session["user_id"] = new_user["user_id"]
        session["user_name"] = name
        session["user_email"] = email
        session["user_role"] = "user"

        flash("Account created successfully! You are now logged in.", "success")
        return redirect(url_for('home'))  # Redirect to homepage or dashboard

    return render_template('register.html')

@main.route('/admin_dashboard')
def admin_dashboard():
    """Displays the admin dashboard with unread messages, prayer requests, and events."""

    if 'user_id' not in session or session.get("user_role") != "admin":
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Debug: Print all messages BEFORE filtering
    cursor.execute("""
        SELECT message_id, name, email, message, submitted_at, read_status, archived
        FROM messages
        ORDER BY submitted_at DESC
    """)
    all_messages_debug = cursor.fetchall()
    print("📌 ALL MESSAGES IN DB:", [dict(msg) for msg in all_messages_debug])

    # ✅ Fetch only non-archived messages
    cursor.execute("""
        SELECT message_id, name, email, message, submitted_at, read_status
        FROM messages
        WHERE archived = 0
        ORDER BY submitted_at DESC
    """)
    messages = cursor.fetchall()

    # Debug: Print filtered messages
    print("✅ FILTERED MESSAGES (archived = 0):", [dict(msg) for msg in messages])

    # ✅ Fetch prayer requests
    cursor.execute("""
        SELECT prayer_id, name, email, prayer_request, submitted_at, read_status
        FROM prayer_requests
        WHERE archived = 0
        ORDER BY submitted_at DESC
    """)
    prayer_requests = cursor.fetchall()

    # Debug: Print all prayer requests
    print("📌 ALL PRAYER REQUESTS IN DB:", [dict(req) for req in prayer_requests])

    # ✅ Count unread prayer requests
    cursor.execute("SELECT COUNT(*) FROM prayer_requests WHERE read_status = 0 AND archived = 0")
    unread_prayers = cursor.fetchone()[0]

    # ✅ Fetch all upcoming events
    cursor.execute("""
        SELECT event_id, event_name, event_date, event_time, location, description
        FROM events
        ORDER BY event_date ASC
    """)
    events = cursor.fetchall()

    # Debug: Print all events
    print("📌 ALL EVENTS IN DB:", [dict(event) for event in events])

    conn.close()

    return render_template(
        'admin.html',
        messages=messages,
        prayer_requests=prayer_requests,  # ✅ Pass prayer requests
        unread_prayers=unread_prayers,
        events=events  # ✅ Pass events to the admin template
    )




@main.before_request
def refresh_db():
    """Ensures Flask does not cache old database results."""
    conn = get_db_connection()
    conn.execute("PRAGMA cache_size = -2000")  # Forces query cache to refresh
    conn.commit()
    conn.close()






@main.route('/update_staff_role', methods=['POST'])

def update_staff_role():
    """Allows admins to update staff roles for users."""
    user_id = request.form.get('user_id')
    staff_role = request.form.get('staff_role')  # Can be empty to remove a role

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if user exists
    cursor.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        flash("User not found!", "danger")
        return redirect(url_for('manage_users'))

    # Update staff role in database (handle role removal)
    if not staff_role:
        cursor.execute("UPDATE users SET staff_role = NULL WHERE user_id = ?", (user_id,))
    else:
        cursor.execute("UPDATE users SET staff_role = ? WHERE user_id = ?", (staff_role, user_id))

    conn.commit()
    conn.close()

    flash("Staff role updated successfully!", "success")
    return redirect(url_for('manage_users'))




# Get Involved Pages
@main.route('/getInvolved')
def getInvolved():
    return render_template('get_involved.html')

@main.route('/new_here')
def new_here():
    return render_template('new_here.html')

@main.route('/find_group')
def find_group():
    settings = get_settings()
    content = get_content()

    return render_template('find_group.html',settings=settings, content=content)

@main.route('/update_notification_roles', methods=['POST'])
def update_notification_roles():
    """ Updates the roles that should receive email notifications for specific messages """
    if 'user_role' not in session or session['user_role'] != 'admin':
        return redirect(url_for('home'))

    selected_roles = request.form.getlist('prayer_roles')

    conn = sqlite3.connect('church_database.db')
    cursor = conn.cursor()

    # Clear existing roles for 'prayer_request'
    cursor.execute("DELETE FROM notification_roles WHERE message_type = 'prayer_request'")

    # Insert new roles
    for role in selected_roles:
        cursor.execute("INSERT INTO notification_roles (message_type, role) VALUES (?, ?)", ('prayer_request', role))

    conn.commit()
    conn.close()

    flash("Updated prayer request notification roles!", "success")
    return redirect(url_for('customize_website'))


@main.route('/remove_notification_role/<role>')
def remove_notification_role(role):
    """ Remove a role from the notification list """
    if 'user_role' not in session or session['user_role'] != 'admin':
        return redirect(url_for('home'))

    conn = sqlite3.connect('church_database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notification_roles WHERE message_type = 'prayer_request' AND role = ?", (role,))
    conn.commit()
    conn.close()

    flash(f"Removed {role} from prayer request notifications.", "warning")
    return redirect(url_for('customize_website'))

@main.route('/customize_website', methods=['GET', 'POST'])
def customize_website():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # ✅ Update general settings
        new_settings = {
            "enable_prayer_requests": request.form.get("prayer_requests_status", "disabled"),
            "enable_newsletter": request.form.get("newsletter_status", "disabled"),
            "enable_donations": request.form.get("donations_status", "disabled"),
            "enable_forums": request.form.get("forums_status", "disabled"),
            "enable_events": request.form.get("events_status", "disabled"),
            "enable_gallery": request.form.get("gallery_status", "disabled"),

            # ✅ Page Settings
            "enable_home": request.form.get("home_status", "disabled"),
            "enable_about": request.form.get("about_status", "disabled"),
            "enable_watch": request.form.get("watch_status", "disabled"),
            "enable_ministries": request.form.get("ministries_status", "disabled"),
            "enable_give": request.form.get("give_status", "disabled"),
            "enable_contact": request.form.get("contact_status", "disabled"),

            # ✅ General Settings
            "site_title": request.form.get("site_title", "My Website"),
            "site_theme": request.form.get("site_theme", "light"),
            "maintenance_mode": request.form.get("maintenance_mode", "disabled")
        }

        # ✅ Update all settings in the database
        for key, value in new_settings.items():
            cursor.execute("UPDATE settings SET status = ? WHERE feature_name = ?", (value, key))

        # ✅ Update Notification Roles - Fixing Multiple Role Selection Without Overwriting
        if 'prayer_roles' in request.form:
            selected_roles = set(request.form.getlist('prayer_roles'))  # Get selected roles as a set

            # Get currently stored roles for prayer requests
            cursor.execute("SELECT role FROM notification_roles WHERE message_type = 'prayer_request'")
            existing_roles = {row["role"] for row in cursor.fetchall()}

            # ✅ Find roles to add (selected but not in the database yet)
            roles_to_add = selected_roles - existing_roles
            for role in roles_to_add:
                cursor.execute("INSERT INTO notification_roles (message_type, role) VALUES ('prayer_request', ?)", (role,))

            # ✅ Keep old roles, **do not delete all** unless they were explicitly removed
            # We only remove roles that were unchecked
            roles_to_remove = existing_roles - selected_roles
            for role in roles_to_remove:
                cursor.execute("DELETE FROM notification_roles WHERE message_type = 'prayer_request' AND role = ?", (role,))

        conn.commit()
        conn.close()
        return redirect(url_for('customize_website'))

    # ✅ Retrieve Settings & Notification Roles
    settings = get_settings()

    cursor.execute("SELECT role FROM notification_roles WHERE message_type = 'prayer_request'")
    prayer_roles = [row["role"] for row in cursor.fetchall()]  # Retrieve multiple roles

    conn.close()

    return render_template("customize_website.html", settings=settings, prayer_roles=prayer_roles)



@main.route('/sign_up_group', methods=['POST'])
def sign_up_group():
    """Handles user sign-ups for small groups."""
    name = request.form.get('name')
    email = request.form.get('email')
    group = request.form.get('group')

    if not name or not email or not group:
        flash("All fields are required to sign up for a group!", "error")
        return redirect(url_for('find_group'))

    # ✅ Save sign-up info to database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO group_signups (name, email, group_name, submitted_at) 
        VALUES (?, ?, ?, datetime('now'))
    """, (name, email, group))
    conn.commit()
    conn.close()

    flash(f"Successfully signed up {name} for {group}!", "success")
    return redirect(url_for('find_group'))


@main.route('/submit_message', methods=['POST'])
def submit_message():
    """Handles message submission and saves group interest correctly."""
    name = request.form.get('name')
    email = request.form.get('email')
    message_type = request.form.get('message_type')  # Expected 'group_signup'
    group_selected = request.form.get('group_selected')

    # 🔹 Debugging Print Statements
    print("DEBUG: message_type =", message_type)
    print("DEBUG: group_selected =", group_selected)

    # ✅ Ensure message text is formatted correctly
    if message_type == "group_signup" and group_selected:
        message_text = f"Group Interested: {group_selected}"
    else:
        message_text = request.form.get('message', "No message provided")  # Default message

    submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Timestamp

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Store message in the database
        cursor.execute(
            "INSERT INTO messages (name, email, message, message_type, submitted_at, read_status) VALUES (?, ?, ?, ?, ?, 0)",
            (name, email, message_text, message_type, submitted_at)
        )
        conn.commit()

        flash("Your message has been submitted!", "success")

    except Exception as e:
        conn.rollback()
        print(f"❌ Error processing message submission: {e}")
        flash("An error occurred. Please try again later.", "danger")

    finally:
        conn.close()

    # ✅ Ensure function **ALWAYS RETURNS A RESPONSE**
    return redirect(url_for('find_group'))







@main.route('/submit_prayer', methods=['POST'])
def submit_prayer():
    """Handles submission of prayer requests."""
    if 'user_id' not in session:
        flash("You need to be logged in to submit a prayer request.", "error")
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ Fetch user's name and email
    cursor.execute("SELECT name, email FROM users WHERE user_id = ?", (user_id,))
    user_data = cursor.fetchone()

    if not user_data:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    user_name, user_email = user_data

    # ✅ Capture and validate prayer text
    prayer_text = request.form.get('prayer_request')

    if not prayer_text or not prayer_text.strip():
        flash("Prayer request cannot be empty.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    # ✅ Check for length constraints (assuming max 500 chars)
    if len(prayer_text) > 500:
        flash("Prayer request is too long. Please limit it to 500 characters.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    try:
        # ✅ Insert prayer request into database
        cursor.execute("""
            INSERT INTO prayer_requests 
            (user_id, name, email, prayer_request, urgency, private, read_status, submitted_at) 
            VALUES (?, ?, ?, ?, 'normal', 0, 0, datetime('now'))
        """, (user_id, user_name, user_email, prayer_text))

        conn.commit()
        flash("Your prayer request has been submitted.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"An error occurred while submitting your request: {str(e)}", "error")

    finally:
        conn.close()

    return redirect(url_for('user_dashboard', user_id=user_id))



@main.route('/delete_user_prayer', methods=['POST'])
def delete_user_prayer():
    """Allows users to delete their own prayer requests and ensures proper deletion."""

    if 'user_id' not in session:
        flash("You need to be logged in to delete a prayer request.", "error")
        return redirect(url_for('login'))

    user_id = int(session['user_id'])
    prayer_id = request.form.get('prayer_id')

    print(f"🔍 Received prayer_id: {prayer_id}, User ID: {user_id}")  # Debugging

    if not prayer_id or prayer_id.strip() == "":
        flash("Invalid prayer request. No prayer_id provided.", "error")
        return redirect(url_for('user_dashboard', user_id=user_id))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verify if the prayer exists BEFORE deletion
    cursor.execute("SELECT * FROM prayer_requests WHERE prayer_id = ? AND user_id = ?", (prayer_id, user_id))
    prayer = cursor.fetchone()

    if not prayer:
        print(f"❌ ERROR: Prayer ID {prayer_id} NOT FOUND in DB before deletion.")
        flash("Prayer request not found or does not belong to you.", "error")
    else:
        print(f"✅ FOUND: Prayer ID {prayer_id} in DB before deletion. Proceeding with delete.")
        
        cursor.execute("DELETE FROM prayer_requests WHERE prayer_id = ?", (prayer_id,))
        conn.commit()

        # Verify if the deletion actually happened
        cursor.execute("SELECT * FROM prayer_requests WHERE prayer_id = ?", (prayer_id,))
        still_exists = cursor.fetchone()

        if still_exists:
            print(f"❌ ERROR: Prayer ID {prayer_id} STILL EXISTS in DB after deletion!")
            flash("Error deleting prayer. Please try again.", "error")
        else:
            print(f"✅ SUCCESS: Prayer ID {prayer_id} deleted.")
            cursor.execute("SELECT COUNT(*) FROM prayer_requests WHERE user_id = ?", (user_id,))
            remaining_prayers = cursor.fetchone()[0]

            if remaining_prayers == 0:
                flash("You have deleted all your prayer requests.", "info")
            else:
                flash("Prayer request deleted successfully.", "success")

    conn.close()
    return redirect(url_for('user_dashboard', user_id=user_id))







@main.route('/prayer_request', methods=['GET', 'POST'])
def prayer_request():
    settings = get_settings()
    content = get_content()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        prayer_request = request.form.get('prayer')
        urgency = request.form.get('urgency')
        private = 1 if 'private' in request.form else 0  # Checkbox: 1 = Private, 0 = Public
        submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Timestamp

        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO prayer_requests (name, email, prayer_request, urgency, private, submitted_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, email, prayer_request, urgency, private, submitted_at))
        conn.commit()

        # ✅ Fetch roles that should receive prayer requests
        cursor.execute("SELECT role FROM notification_roles WHERE message_type = 'prayer_request'")
        roles_to_notify = [row[0] for row in cursor.fetchall()]

        # ✅ Get emails of users with those roles
        recipient_emails = []
        if roles_to_notify:
            placeholders = ",".join(["?"] * len(roles_to_notify))
            query = f"SELECT email FROM users WHERE staff_role IN ({placeholders})"
            cursor.execute(query, roles_to_notify)
            recipient_emails = [row[0] for row in cursor.fetchall()]

        conn.close()

        # ✅ Send email only if there are recipients
        if recipient_emails:
            subject = "📩 New Prayer Request Submitted"
            email_body = f"""
            <h2>New Prayer Request Received</h2>
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Urgency Level:</strong> {urgency}</p>
            <p><strong>Private:</strong> {"Yes" if private else "No"}</p>
            <p><strong>Prayer Request:</strong></p>
            <blockquote>{prayer_request}</blockquote>
            <p><strong>Submitted At:</strong> {submitted_at}</p>
            """
            send_email(subject, recipient_emails, email_body)

        return render_template('prayer_request.html', success=True, settings=settings, content=content)

    return render_template('prayer_request.html', unread_prayers=5, total_prayers=10, content=content, settings=settings)



@main.route('/prayer_team')
def prayer_team():
    return render_template('prayer_team.html')

@main.route('/community_outreach')
def community_outreach():
    return render_template('community_outreach.html')

# Leadership and Church Info
@main.route('/leadership')
def leadership():
    settings = get_settings()
    content = get_content()

    # Connect to the database
    conn = sqlite3.connect('church_database.db')
    cursor = conn.cursor()
    
    # Fetch users who have an 'admin' role (leadership staff)
    cursor.execute("SELECT name, role FROM users WHERE role = 'admin'")
    staff = [{'name': row[0], 'staff_role': row[1]} for row in cursor.fetchall()]
    
    conn.close()

    return render_template('leadership.html', settings=settings, content=content, staff=staff)



@main.route('/media')
def media():
    return render_template('media.html')


@main.route('/jobs')
def jobs():
    return render_template('jobs.html')

@main.route('/church_locations')
def church_locations():
    return render_template('church_locations.html')

@main.route('/directions')
def directions():
    return render_template('directions.html')


@main.route('/community_forums')
def community_forums():
    conn = get_db_connection()
    topics = conn.execute(
        "SELECT id, title, author, category, created_at, (SELECT COUNT(*) FROM replies WHERE topic_id = topics.id) AS replies_count FROM topics ORDER BY created_at DESC LIMIT 10"
    ).fetchall()

    #if forms are disabled redirect to home
    settings = get_settings()
    if settings.get("enable_forums") == "disabled":
        return redirect(url_for('home'))
    
    conn.close()
    return render_template('community_forums.html', topics=topics)

@main.route('/forum_category/<category>')
def forum_category(category):
    conn = get_db_connection()
    topics = conn.execute(
        "SELECT id, title, author, created_at FROM topics WHERE category = ? ORDER BY created_at DESC",
        (category,)
    ).fetchall()
    conn.close()
    return render_template('forum_category.html', category=category, topics=topics)

@main.route('/create_topic', methods=['POST'])
def create_topic():
    if 'user_id' not in session:
        flash("You must be logged in to start a discussion.", "error")
        return redirect(url_for('login'))

    title = request.form['title']
    category = request.form['category']
    content = request.form['content']
    author = session['user_email']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO topics (title, category, content, author, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
        (title, category, content, author)
    )
    conn.commit()
    conn.close()

    flash("Discussion created successfully!", "success")
    return redirect(url_for('community_forums'))

@main.route('/forum_topic/<int:topic_id>')
def forum_topic(topic_id):
    conn = get_db_connection()
    topic = conn.execute("SELECT * FROM topics WHERE id = ?", (topic_id,)).fetchone()
    replies = conn.execute(
        "SELECT * FROM replies WHERE topic_id = ? ORDER BY created_at ASC",
        (topic_id,)
    ).fetchall()
    conn.close()

    if topic is None:
        flash("Topic not found.", "error")
        return redirect(url_for('community_forums'))

    return render_template('forum_topic.html', topic=topic, replies=replies)


@main.route('/post_reply/<int:topic_id>', methods=['POST'])
def post_reply(topic_id):
    if 'user_id' not in session:
        flash("You must be logged in to reply.", "error")
        return redirect(url_for('login'))

    content = request.form['content']
    author = session['user_email']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO replies (topic_id, content, author, created_at) VALUES (?, ?, ?, datetime('now'))",
        (topic_id, content, author)
    )
    conn.commit()
    conn.close()

    flash("Reply posted successfully!", "success")
    return redirect(url_for('forum_topic', topic_id=topic_id))


if __name__ == '__main__':
    main.run(debug=True, port=5050)

