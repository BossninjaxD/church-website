import sqlite3

# Define database file path
db_path = "/Users/mark/Documents/Programing/CodeingProjects/python/ChurchWebsite/church_database.db"

# Connect to SQLite database (creates the file if it doesn't exist)
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create Users Table (for login system)
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Store hashed passwords
    role TEXT CHECK(role IN ('admin', 'user', 'prayer_team')) DEFAULT 'user'
);
""")

# Create Messages Table (Contact Form)
cursor.execute("""
CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# Create Events Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_name TEXT NOT NULL,
    event_date DATE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# Create Event RSVP Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS event_rsvp (
    rsvp_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    response_type TEXT CHECK(response_type IN ('RSVP', 'recommend')) NOT NULL,
    event_id INTEGER NOT NULL,
    additional_details TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
""")

# Create Prayer Requests Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS prayer_requests (
    prayer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    prayer_request TEXT NOT NULL,
    urgency TEXT CHECK(urgency IN ('normal', 'urgent', 'critical')) NOT NULL DEFAULT 'normal',
    private BOOLEAN DEFAULT 0,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# Create Financial Records Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS financial_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    date_given TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    method TEXT CHECK(method IN ('cash', 'check', 'credit_card')) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
""")

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database and tables created successfully!")
