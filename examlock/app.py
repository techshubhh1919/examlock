import time
import base64
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from database import init_db, SessionLocal, ExamPaper, AuditLedger, append_audit_log
from crypto_utils import crypto_service

app = Flask(__name__)
CORS(app)

# Initialize database schema
init_db()

@app.route('/')
def index():
    """Serves the Unified EXAMLOCK Management & Examination Portal."""
    return render_template('index.html')

@app.route('/api/authority/create-exam', methods=['POST'])
def create_and_encrypt_exam():
    """Step 1: Authority Signs, Encrypts, and locks paper."""
    data = request.json or {}
    title = data.get("title", "National Standard Exam 2026")
    exam_code = data.get("exam_code", f"EXAM-{int(time.time())}")
    paper_content = data.get("content", "Question 1: Explain Zero-Trust Architecture.")
    center_id = data.get("center_id", "CENTRE-DELHI-01")
    device_id = data.get("device_id", "DEV-STATION-A")
    delay_seconds = int(data.get("delay_seconds", 30))
    release_timestamp = time.time() + delay_seconds

    # AES-256 Encryption
    aes_key = crypto_service.generate_aes_key()
    encrypted_data = crypto_service.encrypt_paper(paper_content, aes_key)
    
    # RSA Digital Signature over the ciphertext hash
    content_hash = crypto_service.calculate_sha256(encrypted_data["ciphertext"])
    signature = crypto_service.sign_data(content_hash)

    db = SessionLocal()
    try:
        exam = ExamPaper(
            exam_code=exam_code,
            title=title,
            encrypted_payload=encrypted_data["ciphertext"],
            nonce=encrypted_data["nonce"],
            aes_key_b64=base64.b64encode(aes_key).decode('utf-8'),
            digital_signature=signature,
            center_id=center_id,
            device_fingerprint=device_id,
            release_timestamp=release_timestamp
        )
        db.add(exam)
        db.commit()

        # Write to Tamper-Evident Ledger
        append_audit_log(
            "EXAM_CREATED", 
            f"Exam {exam_code} signed and encrypted. Target Centre: {center_id}, Target Device: {device_id}"
        )

        return jsonify({
            "status": "success",
            "message": "Exam encrypted, digitally signed, and registered.",
            "exam_code": exam_code,
            "release_timestamp": release_timestamp,
            "signature": signature[:32] + "..."
        })
    finally:
        db.close()

@app.route('/api/center/unlock-exam', methods=['POST'])
def unlock_exam():
    """Step 2: Time-Locked, Multi-Factor Verification & Decryption."""
    data = request.json or {}
    exam_code = data.get("exam_code")
    center_id = data.get("center_id")
    device_id = data.get("device_id")
    mfa_token = data.get("mfa_token") # Simulating QR / OTP / Biometrics

    db = SessionLocal()
    try:
        exam = db.query(ExamPaper).filter(ExamPaper.exam_code == exam_code).first()
        if not exam:
            return jsonify({"status": "error", "message": "Exam paper not found."}), 404

        current_time = time.time()

        # 1. Multi-Factor Auth Check
        if mfa_token != "AUTH_BIOMETRIC_OK":
            append_audit_log("AUTH_FAILED", f"Unauthorized MFA token attempt for {exam_code}.")
            return jsonify({"status": "error", "message": "Invalid Biometric / OTP Authentication."}), 403

        # 2. Location & Device Binding Check
        if exam.center_id != center_id or exam.device_fingerprint != device_id:
            append_audit_log("DEVICE_MISMATCH", f"Device/Location mismatch on {exam_code}. Provided: {center_id}/{device_id}")
            return jsonify({"status": "error", "message": "Access Denied: Centre or Device fingerprint mismatch."}), 403

        # 3. Time-Lock Check
        if current_time < exam.release_timestamp:
            remaining = int(exam.release_timestamp - current_time)
            append_audit_log("EARLY_ACCESS_PREVENTED", f"Premature unlock attempt on {exam_code}. Locked for {remaining}s.")
            return jsonify({
                "status": "locked", 
                "message": f"Time-lock active. Paper will unlock in {remaining} seconds.",
                "remaining_seconds": remaining
            }), 423

        # 4. Digital Signature Verification
        content_hash = crypto_service.calculate_sha256(exam.encrypted_payload)
        is_valid = crypto_service.verify_signature(content_hash, exam.digital_signature)
        if not is_valid:
            append_audit_log("TAMPER_DETECTED", f"Digital signature mismatch on {exam_code}!")
            return jsonify({"status": "error", "message": "Integrity Check Failed: Signature Mismatch."}), 400

        # 5. Decrypt Paper Content
        key = base64.b64decode(exam.aes_key_b64)
        decrypted_text = crypto_service.decrypt_paper(exam.encrypted_payload, exam.nonce, key)

        append_audit_log("EXAM_UNLOCKED", f"Exam {exam_code} securely unlocked at {center_id} on {device_id}.")

        return jsonify({
            "status": "success",
            "message": "Paper unlocked successfully.",
            "title": exam.title,
            "content": decrypted_text
        })
    finally:
        db.close()

@app.route('/api/proctor/report-incident', methods=['POST'])
def report_proctor_incident():
    """Step 3: Real-time AI Proctoring Malpractice Alert."""
    data = request.json or {}
    incident_type = data.get("incident_type", "ANOMALY")
    confidence = data.get("confidence", "95%")
    details = f"AI Proctor Alert: {incident_type} (Confidence: {confidence})"

    block = append_audit_log("PROCTOR_ALERT", details)
    return jsonify({"status": "recorded", "block": block})

@app.route('/api/audit/trail', methods=['GET'])
def get_audit_trail():
    """Step 4: Tamper-Evident Forensic Audit Trail."""
    db = SessionLocal()
    try:
        logs = db.query(AuditLedger).order_by(AuditLedger.id.asc()).all()
        return jsonify({
            "trail": [
                {
                    "id": l.id,
                    "timestamp": l.timestamp,
                    "event_type": l.event_type,
                    "details": l.details,
                    "previous_hash": l.previous_hash,
                    "block_hash": l.block_hash
                } for l in logs
            ]
        })
    finally:
        db.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)