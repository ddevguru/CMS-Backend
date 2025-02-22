from flask import Flask, request, jsonify, session
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
from datetime import date, time, timedelta, datetime
import threading
import time

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)


db_config = {
    "host": "localhost",
    "user": "root",  
    "password": "",  
    "database": "user_management"
}


VULGAR_WORDS = ["badword1", "badword2", "badword3"]  

UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads") 
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/uploads/<filename>")
def serve_uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

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
    role = data.get('role')  
    photo = data.get('photo')

    if not name or not username or not email or not password or not phone:
        return jsonify({"error": "All fields are required!"}), 400

   
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
        cursor.execute("SELECT id, name, username, email, photo, role, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['photo'] = user['photo']
            session['user_role'] = user['role']

            role_redirects = {
                "user": "/student-dashboard",
                "admin": "/admin-panel",
                "mentor": "/faculty-dashboard",
                "doctor": "/add_report"
            }
            redirect_url = role_redirects.get(user['role'], "/student-dashboard")

            return jsonify({
                "message": "Login successful!",
                "redirect": redirect_url,
                "user": {
                    "id": user['id'],
                    "name": user['name'],  # ✅ Include name
                    "username": user['username'],
                    "email": user['email'],  # ✅ Include email
                    "photo": user['photo'],
                    "role": user['role']
                }
            })
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
    

@app.route('/profile/<int:user_id>', methods=['GET'])

def get_student_profile(user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT name, avatar FROM users WHERE id = %s", (user_id,))
    student = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(student) if student else jsonify({"error": "Student not found"}), 404

# @app.route('/api/student/dashboard/<int:user_id>', methods=['GET'])
# def get_dashboard_data(user_id):
#     conn = mysql.connector.connect(**db_config)
#     cursor = conn.cursor()
#     cursor.execute("SELECT notices, courses, upcoming_events FROM dashboard WHERE student_id = %s", (user_id,))
#     dashboard_data = cursor.fetchone()
#     return jsonify(dashboard_data) if dashboard_data else jsonify({"error": "Data not found"}), 404


@app.route('/api/voters', methods=['GET'])
def get_voters():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)  # Dictionary cursor to fetch column names
        cursor.execute("SELECT id, full_name, role, photo FROM candidates")
        voters = cursor.fetchall()  # Fetch all results
    except mysql.connector.Error as err:
        return jsonify({"success": False, "error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

    # Format results
    result = [
        {
            "id": voter["id"],
            "full_name": voter["full_name"],
            "role": voter["role"],
            "photo": f"http://127.0.0.1:5000/uploads/{voter['photo']}" if voter["photo"] else None
        }
        for voter in voters
    ]
    return jsonify({"success": True, "data": result}), 200


@app.route('/api/check_vote', methods=['GET'])
def check_vote():
    user_id = request.args.get("user_id")
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as count FROM votes WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify({"voted": result["count"] > 0})

@app.route('/api/vote', methods=['POST'])
def vote():
    data = request.json
    user_id = data.get("user_id")
    candidate_id = data.get("candidate_id")

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM votes WHERE user_id = %s", (user_id,))
    if cursor.fetchone()[0] > 0:
        return jsonify({"success": False, "message": "You have already voted!"})

    cursor.execute("INSERT INTO votes (user_id, candidate_id) VALUES (%s, %s)", (user_id, candidate_id))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True, "message": "Vote cast successfully!"})
@app.route("/facilities", methods=["GET"])
def get_facilities():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, status FROM facilities")
        facilities = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({"data": facilities})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/book", methods=["POST"])
def book_facility():
    data = request.json
    user_name = data.get("user_name")
    user_email = data.get("user_email")
    facility_id = data.get("facility_id")
    booking_date = data.get("booking_date")
    booking_time = data.get("booking_time")
    duration = int(data.get("duration", 1))  

    if not all([user_name, user_email, facility_id, booking_date, booking_time, duration]):
        return jsonify({"message": "All fields are required"}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Update facility status to 'booked'
        cursor.execute("UPDATE facilities SET status = 'booked' WHERE id = %s", (facility_id,))
        conn.commit()

        # Insert the booking record
        cursor.execute("""
            INSERT INTO bookings (user_name, user_email, facility_id, booking_date, booking_time, duration)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_name, user_email, facility_id, booking_date, booking_time, duration))
        conn.commit()

        # Schedule facility status reset
        threading.Thread(target=reset_facility_status, args=(facility_id, duration)).start()

        return jsonify({"message": "Booking successful!"}), 201
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def reset_facility_status(facility_id, duration):
    time.sleep(duration * 3600)  # Convert hours to seconds
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("UPDATE facilities SET status = 'available' WHERE id = %s", (facility_id,))
    conn.commit()
    cursor.close()
    conn.close()
@app.route('/approve_booking', methods=['POST'])
def approve_booking():
    data = request.json
    booking_id = data.get("booking_id")
    action = data.get("action")  # 'approve' or 'reject'

    if not booking_id or action not in ["approve", "reject"]:
        return jsonify({"message": "Invalid request"}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        new_status = "approved" if action == "approve" else "rejected"
        query = "UPDATE bookings SET status = %s WHERE id = %s"
        cursor.execute(query, (new_status, booking_id))
        conn.commit()

        return jsonify({"message": f"Booking {new_status} successfully."}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/bookings', methods=['GET'])
def get_bookings():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT id, user_name, user_email, facility_id, booking_date, booking_time, status FROM bookings"
        cursor.execute(query)
        bookings = cursor.fetchall()

        # Convert timedelta and datetime to string format
        for booking in bookings:
            if isinstance(booking['booking_date'], (date, datetime)):
                booking['booking_date'] = booking['booking_date'].strftime("%Y-%m-%d")  # Convert date to string
            if isinstance(booking['booking_time'], (timedelta, time)):
                booking['booking_time'] = str(booking['booking_time'])  # Convert time to string

        cursor.close()
        conn.close()

        return jsonify({"bookings": bookings}), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    
    
@app.route('/booking', methods=['GET'])
def get_all_bookings():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT b.id, b.user_name, b.user_email, f.name AS facility_name, 
                   b.booking_date, b.booking_time, b.duration, b.booking_end_time, b.created_at
            FROM bookings b
            JOIN facilities f ON b.facility_id = f.id
            ORDER BY b.booking_date DESC, b.booking_time DESC
        """
        cursor.execute(query)
        bookings = cursor.fetchall()

        # Convert date & time fields to string format
        for booking in bookings:
            booking["booking_date"] = str(booking["booking_date"])
            booking["booking_time"] = str(booking["booking_time"])
            booking["booking_end_time"] = str(booking["booking_end_time"])
            booking["created_at"] = str(booking["created_at"])

        cursor.close()
        conn.close()

        return jsonify({"booking": booking}), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
@app.route('/submit_application', methods=['POST'])
def submit_application():
    data = request.json
    user_id = data.get('user_id')  
    title = data.get('title')
    description = data.get('description')
    category = data.get('category')

    print(f"Received data: {data}")  # Debugging

    if not user_id or not title or not description or not category:
        return jsonify({"error": "All fields are required"}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO applications (user_id, title, description, category) VALUES (%s, %s, %s, %s)",
            (user_id, title, description, category)
        )
        conn.commit()

        cursor.close()
        conn.close()
        
        return jsonify({"message": "Application submitted successfully!"})

    except mysql.connector.Error as err:
        print(f"Database error: {err}")  # Debugging
        return jsonify({"error": "Database error occurred"}), 500



@app.route('/applications', methods=['GET'])
def get_applications():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Fetch application details along with the applicant's name
        query = """
        SELECT applications.id, users.name AS applicant_name, applications.title, 
               applications.description, applications.category, applications.status, applications.created_at
        FROM applications
        JOIN users ON applications.user_id = users.id
        """

        cursor.execute(query)
        result = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()

        if not result:
            return jsonify({'message': 'No applications found'}), 404
        
        return jsonify(result)
    
    except Exception as e:
        print(f"Error: {e}")  # Logs error in terminal
        return jsonify({'error': str(e)}), 500


# Approve Application (Admin Only)
@app.route('/update_application/<int:app_id>', methods=['OPTIONS'])
def handle_preflight(app_id):
    response = jsonify({"message": "Preflight request OK"})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    return response, 200

# Update application status API
@app.route('/update_application/<int:app_id>', methods=['POST'])
def update_application(app_id):
    try:
        data = request.get_json()
        new_status = data.get('status')

        if not new_status:
            return jsonify({'error': 'Status is required'}), 400

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        query = "UPDATE applications SET status = %s WHERE id = %s"
        cursor.execute(query, (new_status, app_id))
        
        conn.commit()
        cursor.close()
        conn.close()


        return jsonify({'message': 'Application updated successfully'}), 200
    
    except Exception as e:
        print(f"Error: {e}")  # Logs error in terminal
        return jsonify({'error': str(e)}), 500

@app.route('/application', methods=['GET'])
def get_application():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Fetch application details along with the applicant's name
        query = """
        SELECT applications.id, users.name AS applicant_name, applications.title, 
               applications.description, applications.category, applications.status, applications.created_at
        FROM applications
        JOIN users ON applications.user_id = users.id
        """

        cursor.execute(query)
        result = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()

        if not result:
            return jsonify({'message': 'No applications found'}), 404
        
        return jsonify(result)
    
    except Exception as e:
        print(f"Error: {e}")  # Logs error in terminal
        return jsonify({'error': str(e)}), 500


def contains_vulgar_content(text):
    """Check if the complaint contains any vulgar words."""
    for word in VULGAR_WORDS:
        if word in text.lower():
            return True
    return False

@app.route("/submit_complaint", methods=["POST"])
def submit_complaint():
    data = request.json
    complaint_text = data.get("complaint", "")

    if not complaint_text:
        return jsonify({"error": "Complaint cannot be empty"}), 400

    # Check for vulgar content
    contains_vulgar = contains_vulgar_content(complaint_text)
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    # Store the complaint in the database
    query = "INSERT INTO complaints (complaint) VALUES (%s)"
    cursor.execute(query, (complaint_text,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "message": "Complaint submitted successfully",
        "warning": "Complaint contains inappropriate words" if contains_vulgar else None
    })
    
@app.route('/get_complaints', methods=['GET'])
def get_complaints():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT id, complaint, submitted_at FROM complaints ORDER BY submitted_at DESC"
        cursor.execute(query)
        result = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(result)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/add_cheating_record", methods=["POST"])
def add_cheating_record():
    data = request.json
    student_name = data.get("student_name")
    reason = data.get("reason")
    proof = data.get("proof")  # Image or document URL

    if not student_name or not reason or not proof:
        return jsonify({"error": "All fields are required"}), 400
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    query = "INSERT INTO cheating_records (student_name, reason, proof) VALUES (%s, %s, %s)"
    cursor.execute(query, (student_name, reason, proof))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Record added successfully"}), 201

# Route to fetch cheating records
@app.route("/cheating_records", methods=["GET"])
def get_cheating_records():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Fetch records from cheating_records table
        cursor.execute("SELECT * FROM cheating_records ORDER BY reported_at DESC")
        records = cursor.fetchall()
        
        conn.commit()
        cursor.close()
        conn.close()

        # Directly return the JSON response as records are already dictionaries
        return jsonify(records)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/upload', methods=['POST'])
def upload_budget():
    title = request.form['title']
    amount = request.form['amount']
    category = request.form['category']
    proof = request.files['proof']

    # Save proof file
    filename = proof.filename
    proof.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    # Insert into database
    sql = "INSERT INTO budgets (title, amount, category, proof) VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (title, amount, category, filename))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Budget uploaded successfully"}), 201

# API to get all budgets
@app.route('/get_budgets', methods=['GET'])
def get_budgets():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM budgets")
    budgets = cursor.fetchall()

    budget_list = []
    for budget in budgets:
        budget_list.append({
            "id": budget["id"],           # ✅ Use dictionary key
            "title": budget["title"],     # ✅ Use dictionary key
            "amount": budget["amount"],   # ✅ Use dictionary key
            "category": budget["category"],  # ✅ Use dictionary key
            "proof": budget["proof"]      # ✅ Use dictionary key
        })
    
    cursor.close()
    conn.close()
    return jsonify(budget_list)


# API to serve proof files
@app.route('/uploads/<filename>')
def get_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/add_report', methods=['POST'])
def add_report():
    try:
        data = request.json
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO student_reports (student_name, age, symptoms, diagnosis, prescribed_medicine, remarks)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (data['student_name'], data['age'], data['symptoms'], data['diagnosis'], data['prescribed_medicine'], data['remarks']))
        
        conn.commit()  
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Report added successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get All Reports
@app.route('/reports', methods=['GET'])
def get_reports():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM student_reports")
    reports = cursor.fetchall()
    
    cursor.close()
    conn.close()
    return jsonify(reports)

if __name__ == '__main__':
    app.run(debug=True)
