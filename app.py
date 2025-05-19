import os, datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash
)
import firebase_admin
from functools import wraps
from firebase_admin import credentials, firestore, auth
import requests

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db_firestore = firestore.client()


app = Flask(__name__)
app.secret_key = 'lksdfsdfkjfneofweofskf9204392358342' # might need to change later


FIREBASE_WEB_API_KEY = "AIzaSyDnMJOweajBQaCJ3MzJKomF-xYyYJJKkaU"
FIREBASE_AUTH_SIGN_IN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_uid' not in session: # Check if user_uid is in session
            flash("You need to be logged in to view this page.", "warning")
            return redirect(url_for('login', next=request.url)) # Redirect to login, pass current URL as next
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def home():
    user_uid = session.get('user_uid')
    return render_template("home.html", active_page='home')


@app.route('/profile')
@login_required
def profile():
    user_uid = session.get('user_uid')
    # Fetch profile data for user_uid from Firestore
    try:
        user_doc = db_firestore.collection('users').document(user_uid).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            return render_template("profile.html", active_page='profile', user=user_data)
        else:
            flash("User profile not found.", "error")
            return redirect(url_for('login'))
    except Exception as e:
        flash(f"Error fetching profile: {e}", "error")
        return redirect(url_for('login'))
    

@app.route('/logout')
@login_required
def logout():
    session.pop('user_uid', None)
    session.pop('user_email', None)
    session.pop('display_name', None)

    flash("You have been successfully logged out.", "info")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for('login'))

        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        try:
            response = requests.post(FIREBASE_AUTH_SIGN_IN_URL, json=payload)
            response_data = response.json()

            if response.status_code == 200:
                user_uid = response_data.get('localId')
                user_email = response_data.get('email')
                
                try:
                    firebase_user = auth.get_user(user_uid)
                    display_name = firebase_user.display_name or user_email
                except Exception as e:
                    print(f"Could not fetch Firebase user details for display name: {e}")

                session.clear()
                session['user_uid'] = user_uid
                session['user_email'] = user_email
                session['display_name'] = display_name # Store display name in session

                flash(f"Welcome back, {display_name}!", "success")
                
                next_url = request.args.get('next')
                if next_url:
                    return redirect(next_url)
                return redirect(url_for('home'))
            else:
                error_message = response_data.get("error", {}).get("message", "Invalid credentials or user not found.")
                if error_message == "EMAIL_NOT_FOUND":
                    flash("Email not found. Please check your email or sign up.", "error")
                elif error_message == "INVALID_PASSWORD": # For Firebase, it's usually INVALID_LOGIN_CREDENTIALS or similar for REST
                    flash("Invalid password. Please try again.", "error")
                elif error_message == "INVALID_LOGIN_CREDENTIALS": # More common Firebase error message
                     flash("Invalid email or password. Please try again.", "error")
                else:
                    flash(f"Login failed: {error_message}", "error")
                return redirect(url_for('login'))

        except requests.exceptions.RequestException as e:
            flash(f"Network error during login: {e}", "error")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An unexpected error occurred during login: {e}", "error")
            print(f"Login error: {e}") # For debugging
            return redirect(url_for('login'))

    return render_template("login.html") # For GET request


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        pet_names_str = request.form.get('pet_names', '')

        if not all([username, email, password, confirm_password]):
            flash("All fields except pet names are required.", "error")
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))
        
        try:
            user_record = auth.create_user(
                email=email,
                password=password,
                display_name=username  # Optional: sets display name in Firebase Auth
            )
            print(f"Successfully created new user: {user_record.uid}")

            pet_names_list = [name.strip() for name in pet_names_str.split(',') if name.strip()]

            user_data = {
                'username': username,
                'email': email,
                # DO NOT store the password in Firestore. Auth handles it.
                'pet_names': pet_names_list,
                'created_at': firestore.SERVER_TIMESTAMP # Good practice
            }

            # Use the Firebase Auth UID as the document ID in Firestore
            db_firestore.collection('users').document(user_record.uid).set(user_data)
            print(f"User data stored in Firestore for UID: {user_record.uid}")

            session.clear() # Clear any old session data just in case
            session['user_uid'] = user_record.uid
            session['user_email'] = user_record.email # Optional: store email
            session['display_name'] = user_record.display_name

            flash(f"Welcome, {username}!")
            return redirect(url_for('home')) # Redirect to login page after successful signup

        except firebase_admin.auth.EmailAlreadyExistsError:
            flash("This email address is already in use.", "error")
            print(f"Error: Email {email} already exists.")
            return redirect(url_for('signup'))
        except Exception as e:
            flash(f"An error occurred during signup: {e}", "error")
            print(f"An unexpected error occurred: {e}")
            return redirect(url_for('signup'))

    # For GET request, just render the signup page
    return render_template("signup.html", active_page='signup')


# ------------------Firebase Test------------------------
@app.route("/test-firebase")
def test_firebase():
    try:
        doc_ref = db_firestore.collection(u'test').document(u'connection')
        doc_ref.set({u'connected': True})
        return "Firebase Firestore write succeeded!"
    except Exception as e:
        print(f"Detailed error: {e}")
        return f"Firebase Firestore write failed: {str(e)}"


if __name__ == "__main__":
    app.run(debug=True)