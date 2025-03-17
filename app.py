from flask import Flask, jsonify, request
import firebase_admin
from firebase_admin import auth, credentials
from flask_cors import CORS
import os
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://0.0.0.0:8000", "http://100.115.92.201:5000"]}}, supports_credentials=True)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(os.path.join(os.getcwd(), "firebase_credentials.json"))
firebase_admin.initialize_app(cred)

# Set up Rate Limiting (limit to 5 requests per minute per IP)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

# Set up Logging
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

@app.errorhandler(429)
def ratelimit_error(e):
    logging.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({"success": False, "error": "Too many requests, please try again later."}), 429

@app.errorhandler(Exception)
def global_error_handler(e):
    logging.error(f"Unexpected error: {str(e)}")
    return jsonify({"success": False, "error": "An unexpected error occurred."}), 500

@app.route("/verify_biometric", methods=["POST", "OPTIONS"])
@limiter.limit("5 per minute")
def verify_biometric():
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight request successful"})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    
    try:
        data = request.get_json()
        id_token = data.get("idToken")

        if not id_token:
            return jsonify({"success": False, "error": "No token provided"}), 400

        decoded_token = auth.verify_id_token(id_token)
        user_id = decoded_token.get("uid", "")
        user_email = decoded_token.get("email", "")

        logging.info(f"Biometric authentication successful for {user_email} (UID: {user_id})")
        return jsonify({
            "success": True,
            "message": "Biometric Authentication Successful",
            "user": {
                "uid": user_id,
                "email": user_email
            }
        })

    except firebase_admin.auth.ExpiredIdTokenError:
        logging.warning("Expired ID Token received")
        return jsonify({"success": False, "error": "Expired ID Token"}), 401
    
    except firebase_admin.auth.InvalidIdTokenError:
        logging.warning("Invalid ID Token received")
        return jsonify({"success": False, "error": "Invalid ID Token"}), 401

    except Exception as e:
        logging.error(f"Error in verify_biometric: {str(e)}")
        return jsonify({"success": False, "error": "Internal Server Error"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
