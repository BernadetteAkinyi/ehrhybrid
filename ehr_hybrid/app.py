# corrected app.py - Hybrid EHR (cleaned & unified)
from flask import Flask, render_template, request, redirect, session, flash, url_for
import mysql.connector
from dotenv import load_dotenv
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

# Connect to MySQL
db = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)
cursor = db.cursor(dictionary=True)

# ---------------------
# Helper / Logging
# ---------------------
def log_access(user_id, patient_id, action, result, reason=""):
    """
    Unified logging helper (writes to access_logs).
    patient_id may be None for non-patient actions.
    """
    cursor.execute("""
        INSERT INTO access_logs (user_id, patient_id, action, access_result, justification)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, patient_id, action, result, reason))
    db.commit()

def log_action(user_id, action, details=""):
    """
    Backwards-compatible logging for generic actions.
    Stores an INFO record in access_logs.
    """
    cursor.execute("""
        INSERT INTO access_logs (user_id, patient_id, action, access_result, justification)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, None, action, "INFO", details))
    db.commit()

# ---------------------
# Hybrid Access Engine
# ---------------------
def check_access(user, patient, context):
    """
    Centralized decision engine.
    Returns (allowed: bool, reason: str).
    Rules implemented:
      - Emergency override
      - Admin always allowed
      - Time (example) - can be expanded
      - Department matching for Nurses
      - Assigned doctor requirement for Doctors
      - Optional IP/device checks can be added to context
    """
    hour = context.get("time", datetime.now().hour)
    device = context.get("device", "")
    ip = context.get("ip", "")
    emergency = context.get("emergency", False)

    # 1. Emergency override
    if emergency:
        return True, "Emergency override"

    role = user.get('role_name', '')

    # 2. Admin always allowed
    if role == "Admin":
        return True, "Admin full access"

    # 3. Time-based example (optional policy)
    # here we allow 6am-10pm as working hours by default
    if hour < 6 or hour > 22:
        # allow Admin anyway above; Doctors/Nurses may be blocked
        return False, "Access outside allowed working hours"

    # 4. Doctor: must be assigned doctor (or admin)
    if role == "Doctor":
        # patient may have 'assigned_doctor' column
        assigned = patient.get('assigned_doctor')
        # allow if user is assigned or if doctor belongs to same department and policy allows it (we enforce strict assigned here)
        if user.get('user_id') == assigned:
            return True, "Doctor assigned to patient"
        return False, "Doctor not assigned to this patient"

    # 5. Nurse: allow if same department
    if role == "Nurse":
        if user.get('department') == patient.get('department'):
            return True, "Nurse in same department"
        return False, "Nurse not allowed — different department"

    # 6. Receptionist: limited view (maybe only demographics) - treat as deny for full records
    if role == "Receptionist":
        # Receptionists permitted to view demographics only in other parts of app
        return False, "Receptionist not authorized to view full medical records"

    # Default deny
    return False, "No valid access permissions"

# ---------------------
# Routes
# ---------------------
@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login: fetch user by username; verify password with hashing if possible.
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Fetch user and role info
        cursor.execute("""
            SELECT u.*, r.role_name, r.role_id
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = %s
        """, (username,))
        user = cursor.fetchone()

        if not user:
            flash("Invalid username or password.", "danger")
            return render_template('login.html')

        stored_hash = user.get('password_hash')  # might be hashed or plaintext in old DBs
        password_ok = False

        # Try hashed verification first
        try:
            if stored_hash and stored_hash.startswith('pbkdf2:'):
                password_ok = check_password_hash(stored_hash, password)
            else:
                # fallback plain-text compare (legacy)
                password_ok = (password == stored_hash)
        except Exception:
            # safe fallback
            password_ok = (password == stored_hash)

        if not password_ok:
            flash("Invalid username or password.", "danger")
            return render_template('login.html')

        # normalize values to be serializable
        for k, v in list(user.items()):
            if isinstance(v, (bytes, bytearray)):
                user[k] = v.decode()
            elif not isinstance(v, (str, int, float, bool, type(None))):
                user[k] = str(v)

        session['user'] = user
        log_action(user.get('user_id'), "LOGIN", f"User {username} logged in")
        return redirect('/dashboard')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# ---------------------
# Dashboard
# ---------------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    user = session['user']
    role = user.get('role_name')

    # Get user attributes from DB
    cursor.execute("SELECT attribute_name, attribute_value FROM attributes WHERE user_id = %s", (user['user_id'],))
    attrs = cursor.fetchall()
    user_attrs = {a['attribute_name']: a['attribute_value'] for a in attrs}

    # Context for ABAC
    current_hour = datetime.now().hour
    current_location = 'Hospital'  # placeholder for future location checks

    allowed_shift = user_attrs.get('shift', 'day')
    in_shift = (6 <= current_hour < 18) if allowed_shift == 'day' else (current_hour >= 18 or current_hour < 6)
    in_location = (user_attrs.get('location', 'Hospital') == current_location)
    clearance = user_attrs.get('clearance_level', 'low')

    # ABAC conditions (dashboard-level policy)
    access_granted = True
    reason = ""

    if not in_shift:
        access_granted = False
        reason = "Access denied: outside assigned shift."
    elif not in_location:
        access_granted = False
        reason = "Access denied: wrong location."
    elif clearance == 'low' and role != 'Receptionist':
        access_granted = False
        reason = "Access denied: insufficient clearance."

    # RBAC + ABAC filters for patients listing
    patients = []
    if access_granted:
        if role == 'Admin':
            cursor.execute("SELECT * FROM patients")
        elif role == 'Doctor':
            cursor.execute("SELECT * FROM patients WHERE assigned_doctor = %s", (user['user_id'],))
        elif role == 'Nurse':
            cursor.execute("""
                SELECT p.* FROM patients p
                JOIN users u ON p.assigned_doctor = u.user_id
                WHERE u.department = %s
            """, (user['department'],))
        elif role == 'Receptionist':
            cursor.execute("SELECT patient_id, patient_name, gender, age FROM patients")
        patients = cursor.fetchall()

# Load unauthorized access attempts for Admin only
    unauthorized_attempts = []
    if role == "Admin":
        cursor.execute("""
            SELECT a.*, u.full_name AS staff, p.patient_name AS patient
            FROM access_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            WHERE a.access_result = 'DENIED'
            ORDER BY access_time DESC
            LIMIT 5
        """)
        unauthorized_attempts = cursor.fetchall()

    # Log dashboard access
    log_access(user.get('user_id'), None, "VIEW_DASHBOARD", "GRANTED" if access_granted else "DENIED", reason or "Access evaluated")

    if not access_granted:
        return f"<h3>🚫 {reason}</h3><p><a href='/logout'>Logout</a></p>"

    return render_template(
    'dashboard.html',
    user=user,
    patients=patients,
    attributes=user_attrs,
    unauthorized_attempts=unauthorized_attempts
)
# ---------------------
# Logs (admin)
# ---------------------
@app.route('/logs')
def view_logs():
    if 'user' not in session:
        return redirect('/login')

    user = session['user']
    role = user.get('role_name')

    # Only Admin can view logs
    if role != 'Admin':
        flash("Access denied: Admins only.", "danger")
        return redirect('/dashboard')

    # Pagination
    page = int(request.args.get('page', 1))
    limit = 20
    offset = (page - 1) * limit

    # Search functionality
    search = request.args.get('search', '').strip()
    search_query = f"%{search}%"

    if search:
        cursor.execute("""
            SELECT 
                a.log_id, 
                u.full_name AS user_name, 
                p.patient_name, 
                a.action,
                a.access_time, 
                a.access_result, 
                a.justification
            FROM access_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            WHERE u.full_name LIKE %s
               OR p.patient_name LIKE %s
               OR a.action LIKE %s
               OR a.access_result LIKE %s
               OR a.justification LIKE %s
            ORDER BY a.access_time DESC
            LIMIT %s OFFSET %s
        """, (search_query, search_query, search_query, search_query, search_query, limit, offset))
        logs = cursor.fetchall()

        # Count total rows for pagination
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM access_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            WHERE u.full_name LIKE %s
               OR p.patient_name LIKE %s
               OR a.action LIKE %s
               OR a.access_result LIKE %s
               OR a.justification LIKE %s
        """, (search_query, search_query, search_query, search_query, search_query))
    else:
        cursor.execute("""
            SELECT 
                a.log_id, 
                u.full_name AS user_name, 
                p.patient_name, 
                a.action,
                a.access_time, 
                a.access_result, 
                a.justification
            FROM access_logs a
            LEFT JOIN users u ON a.user_id = u.user_id
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            ORDER BY a.access_time DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        logs = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) AS total FROM access_logs")

    total = cursor.fetchone()['total']
    total_pages = (total // limit) + (1 if total % limit > 0 else 0)

    return render_template(
        'logs.html',
        logs=logs,
        user=user,
        page=page,
        total_pages=total_pages,
        search=search
    )

# ---------------------
# Profile (attributes + password)
# ---------------------
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    user_id = user.get('user_id')

    def load_attributes(uid):
        cursor.execute("SELECT attribute_name, attribute_value FROM attributes WHERE user_id = %s", (uid,))
        rows = cursor.fetchall()
        return {r['attribute_name']: r['attribute_value'] for r in rows}

    def upsert_attribute(uid, name, value):
        cursor.execute("SELECT attribute_id FROM attributes WHERE user_id=%s AND attribute_name=%s", (uid, name))
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "UPDATE attributes SET attribute_value=%s WHERE user_id=%s AND attribute_name=%s",
                (value, uid, name)
            )
        else:
            cursor.execute(
                "INSERT INTO attributes (user_id, attribute_name, attribute_value) VALUES (%s, %s, %s)",
                (uid, name, value)
            )

    # ---------- Handle profile (attributes) update ----------
    if request.method == 'POST' and request.form.get('update_profile'):
        location = request.form.get('location', '').strip()
        shift = request.form.get('shift', '').strip()
        clearance = request.form.get('clearance_level', '').strip()

        if location:
            upsert_attribute(user_id, 'location', location)
        if shift:
            upsert_attribute(user_id, 'shift', shift)
        if user.get('role_name') == 'Admin' and clearance:
            upsert_attribute(user_id, 'clearance_level', clearance)

        db.commit()
        flash("✅ Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    # ---------- Handle password change ----------
    if request.method == 'POST' and request.form.get('change_password'):
        old_pw = request.form.get('old_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not (old_pw and new_pw and confirm_pw):
            flash("❌ Please fill all password fields.", "danger")
            return redirect(url_for('profile'))

        if new_pw != confirm_pw:
            flash("❌ New passwords do not match.", "danger")
            return redirect(url_for('profile'))

        cursor.execute("SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            flash("❌ User not found.", "danger")
            return redirect(url_for('profile'))

        stored_hash = row.get('password_hash')
        password_ok = False
        try:
            password_ok = check_password_hash(stored_hash, old_pw)
        except Exception:
            password_ok = (old_pw == stored_hash)

        if not password_ok:
            flash("❌ Incorrect current password.", "danger")
            return redirect(url_for('profile'))

        new_hash = generate_password_hash(new_pw)
        cursor.execute("UPDATE users SET password_hash=%s WHERE user_id=%s", (new_hash, user_id))
        db.commit()
        flash("✅ Password changed successfully!", "success")
        return redirect(url_for('profile'))

    attributes = load_attributes(user_id)
    return render_template('profile.html', user=user, attributes=attributes)

# ---------------------
# Patients - list / add / view / edit / delete
# ---------------------
@app.route('/patients')
def patients():
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    # Department-based access
    cursor.execute("""
        SELECT * FROM patients
        WHERE department = %s OR %s = 'Admin'
    """, (user['department'], user['role_name']))
    patient_list = cursor.fetchall()

    return render_template('patients.html', user=user, patients=patient_list)

@app.route('/patients/add', methods=['GET', 'POST'])
def add_patient():
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    # only Admins and Doctors allowed
    if user.get('role_name') not in ['Admin', 'Doctor']:
        flash("🚫 Access Denied: You cannot add patients.", "danger")
        return redirect('/patients')

    if request.method == 'POST':
        patient_name = request.form.get('patient_name', '').strip()
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        diagnosis = request.form.get('diagnosis', '').strip()

        if not patient_name:
            flash("Please enter a patient name.", "danger")
            return redirect(url_for('add_patient'))

        try:
            age_val = int(age) if age != '' else None
        except ValueError:
            flash("Age must be a number.", "danger")
            return redirect(url_for('add_patient'))

        department = user.get('department', 'General')

        cursor.execute("""
            INSERT INTO patients (patient_name, age, gender, diagnosis, assigned_doctor, department)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (patient_name, age_val, gender, diagnosis, user['user_id'], department))
        db.commit()

        try:
           log_access(user['user_id'], None, "CREATE_PATIENT", "GRANTED", f"Created patient {patient_name}")
        except Exception:
            pass

        flash("✅ Patient added successfully!", "success")
        return redirect('/patients')

    return render_template('add_patient.html', user=user)

@app.route('/patients/view/<int:pid>')
def view_patient(pid):
    if 'user' not in session:
        return redirect('/login')
    
    user = session['user']

    # Fetch patient info
    cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (pid,))
    patient = cursor.fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    # Build context for hybrid engine
    context = {
        "time": datetime.now().hour,
        "ip": request.remote_addr,
        "device": request.user_agent.string,
        "emergency": False
    }

    allowed, reason = check_access(user, patient, context)

    result = "GRANTED" if allowed else "DENIED"
    log_access(user['user_id'], pid, "VIEW_PATIENT", result, reason)

    if not allowed:
     return render_template(
        "emergency_prompt.html",
        user=user,
        patient=patient,
        reason=reason
    )
    return render_template("patient_view.html", user=user, patient=patient)

@app.route('/patients/edit/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    # Admin only can reassign doctors
    cursor.execute("SELECT user_id, full_name FROM users WHERE role_id = 2")  # role_id=2 → Doctor
    doctors = cursor.fetchall()

    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        gender = request.form['gender']
        diagnosis = request.form['diagnosis']
        assigned_doctor = request.form['assigned_doctor']

        cursor.execute("""
            UPDATE patients
            SET patient_name=%s, age=%s, gender=%s, diagnosis=%s, assigned_doctor=%s
            WHERE patient_id=%s
        """, (name, age, gender, diagnosis, assigned_doctor, patient_id))
        db.commit()

        flash("Patient updated successfully!", "success")
        return redirect('/patients')

    return render_template('edit_patient.html', user=user, patient=patient, doctors=doctors)
    
@app.route('/patients/delete/<int:patient_id>')
def delete_patient(patient_id):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    # Admin only can delete
    if user['role_name'] != "Admin":
        flash("Access denied: only Admins can delete.", "danger")
        return redirect('/patients')

    cursor.execute("DELETE FROM patients WHERE patient_id=%s", (patient_id,))
    db.commit()

    flash("Patient deleted successfully!", "success")
    return redirect('/patients')

# ---------------------
# Appointments
# ---------------------
@app.route('/appointments')
def appointments():
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    # Admin sees everything
    if user['role_name'] == "Admin":
        cursor.execute("""
            SELECT a.*, p.patient_name AS patient, u.full_name AS doctor 
            FROM appointments a
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            LEFT JOIN users u ON a.doctor_id = u.user_id
            ORDER BY appointment_date, appointment_time
        """)
    else:
        cursor.execute("""
            SELECT a.*, p.patient_name AS patient, u.full_name AS doctor
            FROM appointments a
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            LEFT JOIN users u ON a.doctor_id = u.user_id
            WHERE a.doctor_id = %s
            ORDER BY appointment_date, appointment_time
        """, (user['user_id'],))

    appointments_list = cursor.fetchall()

    return render_template('appointments.html', user=user, appointments=appointments_list)

@app.route('/appointments/add', methods=['GET', 'POST'])
def add_appointment():
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    # Get all patients the doctor can manage
    cursor.execute("SELECT patient_id, patient_name FROM patients")
    patients = cursor.fetchall()

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        date = request.form.get('date')
        time = request.form.get('time')
        reason = request.form.get('reason')

        cursor.execute("""
            INSERT INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, reason)
            VALUES (%s, %s, %s, %s, %s)
        """, (patient_id, user['user_id'], date, time, reason))

        db.commit()
        flash("Appointment scheduled successfully!", "success")
        return redirect('/appointments')

    return render_template('add_appointment.html', user=user, patients=patients)

@app.route('/appointments/patient/<int:patient_id>')
def appointments_for_patient(patient_id):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    # Show appointments for a given patient (Admin sees all)
    if user['role_name'] == "Admin":
        cursor.execute("""
            SELECT a.*, u.full_name AS doctor
            FROM appointments a
            LEFT JOIN users u ON a.doctor_id = u.user_id
            WHERE a.patient_id = %s
            ORDER BY appointment_date, appointment_time
        """, (patient_id,))
    else:
        # doctor/nurse: restrict depending on role
        cursor.execute("""
            SELECT a.*, u.full_name AS doctor
            FROM appointments a
            LEFT JOIN users u ON a.doctor_id = u.user_id
            WHERE a.patient_id = %s AND (a.doctor_id = %s OR %s = 'Admin')
            ORDER BY appointment_date, appointment_time
        """, (patient_id, user['user_id'], user['role_name']))

    appts = cursor.fetchall()
    return render_template('appointments.html', user=user, appointments=appts)

@app.route('/appointments/update/<int:appointment_id>/<string:new_status>')
def update_appointment(appointment_id, new_status):
    if 'user' not in session:
        return redirect('/login')

    if new_status not in ['Scheduled', 'Completed', 'Cancelled']:
        flash("Invalid status.", "danger")
        return redirect('/appointments')

    cursor.execute("""
        UPDATE appointments SET status=%s WHERE appointment_id=%s
    """, (new_status, appointment_id))
    db.commit()

    flash(f"Appointment marked as {new_status}!", "success")
    return redirect('/appointments')

# ---------------------
# Medical History
# ---------------------
# Compatibility redirect: /patients/history/<id> -> /history/<id> or vice versa
@app.route('/patients/history/<int:patient_id>')
def patients_history_redirect(patient_id):
    return redirect(f"/history/{patient_id}")

@app.route('/history/<int:patient_id>')
def history(patient_id):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    # Fetch patient info
    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    # ---- HYBRID ACCESS ENGINE ----
    context = {
        "time": datetime.now().hour,
        "device": request.user_agent.string,
        "emergency": False
    }

    allowed, reason = check_access(user, patient, context)
    result = "GRANTED" if allowed else "DENIED"

    log_access(user['user_id'], patient_id, "VIEW_HISTORY", result, reason)

    if not allowed:
        flash(f"🚫 Access Denied: {reason}", "danger")
        return redirect('/dashboard')

    # Load medical history records
    cursor.execute("""
        SELECT h.*, u.full_name AS doctor
        FROM medical_history h
        LEFT JOIN users u ON h.prescribed_by = u.user_id
        WHERE h.patient_id=%s
        ORDER BY visit_date DESC
    """, (patient_id,))
    history_list = cursor.fetchall()

    return render_template("history.html", user=user, patient=patient, history=history_list)

@app.route('/history/add/<int:patient_id>', methods=['GET', 'POST'])
def add_history(patient_id):
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    # Hybrid rules (Doctor assigned OR Admin)
    context = {
        "time": datetime.now().hour,
        "device": request.user_agent.string,
        "emergency": False
    }

    allowed, reason = check_access(user, patient, context)
    result = "GRANTED" if allowed else "DENIED"
    log_access(user['user_id'], patient_id, "ADD_HISTORY", result, reason)

    if not allowed:
        flash(f"🚫 You cannot add medical history: {reason}", "danger")
        return redirect(f"/history/{patient_id}")

    if request.method == 'POST':
        visit_date = request.form['visit_date']
        diagnosis = request.form['diagnosis']
        treatment = request.form['treatment']

        cursor.execute("""
            INSERT INTO medical_history (patient_id, visit_date, diagnosis, treatment, prescribed_by)
            VALUES (%s, %s, %s, %s, %s)
        """, (patient_id, visit_date, diagnosis, treatment, user['user_id']))
        db.commit()

        flash("Medical history added successfully!", "success")
        return redirect(f'/history/{patient_id}')

    return render_template('add_history.html', user=user, patient=patient)
    
@app.route('/history/emergency/<int:patient_id>')
def emergency_history(patient_id):
    if 'user' not in session:
        return redirect('/login')

    user = session['user']

    # Fetch patient
    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    # Emergency context
    context = {
        "time": datetime.now().hour,
        "device": request.user_agent.string,
        "emergency": True
    }

    allowed, reason = check_access(user, patient, context)
    result = "GRANTED" if allowed else "DENIED"
    log_access(user['user_id'], patient_id, "EMERGENCY_VIEW_HISTORY", result, reason)

    if not allowed:
        flash("🚫 Emergency override still denied!", "danger")
        return redirect('/dashboard')

    # Load medical history
    cursor.execute("""
        SELECT h.*, u.full_name AS doctor
        FROM medical_history h
        LEFT JOIN users u ON h.prescribed_by = u.user_id
        WHERE h.patient_id=%s
        ORDER BY visit_date DESC
    """, (patient_id,))
    history_list = cursor.fetchall()

    flash("🚨 Emergency override activated. All access rules bypassed.", "warning")
    return render_template('history.html', user=user, patient=patient, history=history_list)

@app.route('/patients/emergency_override/<int:patient_id>', methods=['POST'])
def emergency_override(patient_id):
    if 'user' not in session:
        return redirect('/login')

    user = session['user']
    reason = request.form.get('reason', '').strip()

    if not reason:
        flash("Please provide a justification for emergency override.", "danger")
        return redirect(f"/patients/view/{patient_id}")

    # Log with BREAK_GLASS
    log_access(
        user_id=user['user_id'],
        patient_id=patient_id,
        action="VIEW_PATIENT",
        result="INFO",
        reason=f"BREAK_GLASS / Emergency override: {reason}"
    )

    # Set emergency=True and bypass restrictions
    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()

    return render_template("patient_view.html", user=user, patient=patient, emergency=True)

@app.route('/patients/emergency_prompt/<int:patient_id>')
def emergency_prompt(patient_id):
    if 'user' not in session:
        return redirect('/login')

    cursor.execute("SELECT * FROM patients WHERE patient_id=%s", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        flash("Patient not found.", "danger")
        return redirect('/patients')

    return render_template('emergency_prompt.html', patient=patient)

# ---------------------
# Run app
# ---------------------
if __name__ == '__main__':
    app.run(debug=True)