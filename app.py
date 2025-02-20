from flask import Flask, request, jsonify, session
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Required for session management

# Allow CORS for React Frontend (localhost:3000)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

# MySQL Database Configuration
db_config = {
    "host": "localhost",
    "user": "root",  # Change this to your MySQL username
    "password": "",  # Change this to your MySQL password
    "database": "user_management"
}


# Set the upload folder path

UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")  # Ensure absolute path
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/uploads/<filename>")
def serve_uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# Create 'users' table if it does not exist
def create_table():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            name VARCHAR(100) NOT NULL,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            email VARCHAR(100) UNIQUE NOT NULL,
                            password VARCHAR(255) NOT NULL,
                            phone VARCHAR(15) UNIQUE NOT NULL,
                            role ENUM('user', 'admin', 'mentor', 'student') NOT NULL DEFAULT 'user',
                            photo VARCHAR(255) DEFAULT NULL
                        )''')
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Error: {err}")

# Call the function to create the table
create_table()

# Middleware to add CORS headers manually (if needed)
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid JSON format"}), 400

    name = data.get('name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')
    role = data.get('role', 'user')  # Default role is 'user'
    photo = data.get('photo')

    if not name or not username or not email or not password or not phone:
        return jsonify({"error": "All fields are required!"}), 400

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, username, email, password, phone, role, photo) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                       (name, username, email, hashed_password.decode('utf-8'), phone, role, photo))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "User registered successfully!"}), 201
    except mysql.connector.Error as err:
        if "Duplicate entry" in str(err):
            return jsonify({"error": "Username, Email, or Phone number already exists!"}), 400
        return jsonify({"error": str(err)}), 500

# Login Route with Role-Based Redirection
# Continuing from login route

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid JSON format"}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and Password are required!"}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            session['username'] = user['username']

            # Role-based redirection
            if user['role'] == 'user':
                return jsonify({"message": "Login successful!", "redirect": "/student-dashboard"})
            elif user['role'] == 'admin':
                return jsonify({"message": "Login successful!", "redirect": "/admin-panel"})
            elif user['role'] == 'mentor':
                return jsonify({"message": "Login successful!", "redirect": "/mentor-dashboard"})
            else:
                return jsonify({"error": "Invalid role!"}), 400
        else:
            return jsonify({"error": "Invalid credentials!"}), 400

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/upload_candidate', methods=['POST'])
def upload_candidate():
    full_name = request.form.get('full_name')
    role = request.form.get('role')
    photo = request.files.get('photo')

    if not full_name or not role or not photo:
        return jsonify({"error": "All fields are required"}), 400

    # Save photo
    filename = secure_filename(photo.filename)
    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    photo.save(photo_path)

    # Save to database
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute ( "INSERT INTO candidates (full_name, role, photo) VALUES (%s, %s, %s)", (full_name, role, filename))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Candidate uploaded successfully"}), 201

# API to fetch candidates
@app.route('/get_candidates', methods=['GET'])
def get_candidates():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT id, full_name, role, photo FROM candidates")
        candidates = cursor.fetchall()
        cursor.close()
        conn.close()

        result = [
            {
                "id": candidate[0],
                "full_name": candidate[1],
                "role": candidate[2],
                "photo": f"http://127.0.0.1:5000/uploads/{candidate[3]}"  # Ensure correct localhost URL
            }
            for candidate in candidates
        ]

        return jsonify(result), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



if __name__ == '__main__':
    app.run(debug=True)
