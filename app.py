from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
import firebase_admin
from functools import wraps
from firebase_admin import credentials, firestore, auth, storage
import uuid
import requests
from datetime import timedelta

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'pets-27b3a.firebasestorage.app'
})
db_firestore = firestore.client()
bucket = storage.bucket()


app = Flask(__name__)
app.secret_key = 'lksdfsdfkjfneofweofskf9204392358342' # might need to change later


FIREBASE_WEB_API_KEY = "AIzaSyDnMJOweajBQaCJ3MzJKomF-xYyYJJKkaU"
FIREBASE_AUTH_SIGN_IN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"

app.permanent_session_lifetime = timedelta(days=30)  # Users stay logged in for 30 days


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_uid' not in session: # Check if user_uid is in session
            flash("You need to be logged in to view this page.", "warning")
            return redirect(url_for('login', next=request.url)) # Redirect to login, pass current URL as next
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_unread_notification_count():
    if 'user_uid' in session:  # Check if the user is logged in
        user_uid = session['user_uid']
        try:
            # Query Firestore for notifications that belong to the current user and are unread
            notifications_query = db_firestore.collection('notifications') \
                                              .where('recipient_uid', '==', user_uid) \
                                              .where('is_read', '==', False) \
                                              .stream()  # Use .stream() for iterating documents

            # Count the number of unread notifications
            unread_count = sum(1 for _ in notifications_query)
            
            return dict(unread_notification_count=unread_count)
        except Exception as e:
            # Log any errors that occur during the Firestore query
            print(f"Error fetching unread notification count for UID {user_uid}: {e}")
            # Return 0 in case of an error to prevent site breakage
            return dict(unread_notification_count=0)
    else:
        # If no user is logged in, there are no unread notifications for them
        return dict(unread_notification_count=0)


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
    

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_uid = session.get('user_uid')
    user_ref = db_firestore.collection('users').document(user_uid)
    user_data = user_ref.get().to_dict() or {}

    # Fetch the Auth email
    auth_user = auth.get_user(user_uid)
    auth_email = auth_user.email
    
    if request.method == 'POST':
        username = request.form.get('username')
        bio = request.form.get('bio')
        email = request.form.get('email')
        pet_names = request.form.getlist('pet_names')

        update_data = {}

        # Handle profile image upload
        file = request.files.get('profile_image')
        profile_image_url = user_data.get('profile_image', "")

        if file and file.filename:
            blob = bucket.blob(f'profile_images/{str(uuid.uuid4())}_{file.filename}')
            blob.upload_from_file(file, content_type=file.content_type)
            blob.make_public()
            profile_image_url = blob.public_url
            update_data['profile_image'] = profile_image_url

        # Only include non-empty fields in update
        update_data = {}
        if username:
            update_data['username'] = username
        if bio is not None:  # allow clearing bio
            update_data['bio'] = bio
        if email:
            update_data['email'] = email
        if pet_names is not None:  # always update pet_names (could be empty list)
            update_data['pet_names'] = [n for n in pet_names if n.strip()]
        if file and file.filename:
            update_data['profile_image'] = profile_image_url

        # Update Auth email (Firebase Admin SDK)
        try:
            if email and email != auth_email:
                auth.update_user(user_uid, email=email)
        except Exception as e:
            flash(f"Error updating email: {str(e)}", "danger")
            return render_template('edit_profile.html', user=user_data, auth_email=auth_email)

        # Only update if there's something to update
        if update_data:
            user_ref.update(update_data)
            flash('Profile updated successfully!')
        else:
            flash('No changes to update.')

        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user_data, auth_email=auth_email)


@app.route('/edit_password', methods=['GET', 'POST'])
@login_required
def edit_password():
    if request.method == 'POST':
        user_uid = session.get('user_uid')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash("Please fill out both fields.", "danger")
        elif new_password != confirm_password:
            flash("Passwords do not match.", "danger")
        elif len(new_password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            try:
                auth.update_user(user_uid, password=new_password)
                flash("Password updated successfully!", "success")
                return redirect(url_for('edit_profile'))
            except Exception as e:
                flash(f"Error updating password: {str(e)}", "danger")
    
    return render_template('edit_password.html')
    

@app.route('/logout')
@login_required
def logout():
    session.pop('user_uid', None)
    session.pop('user_email', None)
    session.pop('display_name', None)
    session.clear()

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

                if 'remember_me' in request.form:
                    session.permanent = True
                else:
                    session.permanent = False
                
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
            flash("Passwords don’t match", "signup_error")
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


@app.route('/direct_messages/<conversation_id>', methods=['GET', 'POST'])
@login_required
def direct_messages(conversation_id):
    messages_ref = db_firestore.collection('conversations').document(conversation_id).collection('messages')

    if request.method == 'POST':
        sender = session.get('display_name', 'anonymous')
        text = request.form['message']
        messages_ref.add({
            'sender': sender,
            'text': text,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return redirect(url_for('direct_messages', conversation_id=conversation_id))

    messages = messages_ref.order_by('timestamp').stream()
    message_list = []
    for msg in messages:
        data = msg.to_dict()
        message_list.append({
            'sender': data.get('sender'),
            'text': data.get('text'),
            'timestamp': data.get('timestamp')
        })

    return render_template('direct_messages.html', messages=message_list, conversation_id=conversation_id)


@app.route('/notifications')
@login_required
def notifications_page():
    user_uid = session.get('user_uid')
    
    notifications_query = db_firestore.collection('notifications') \
                                      .where('recipient_uid', '==', user_uid) \
                                      .order_by('timestamp', direction=firestore.Query.DESCENDING) \
                                      .stream()
    
    user_notifications = []
    for notif_doc in notifications_query:
        notif_data = notif_doc.to_dict()
        user_notifications.append({
            'id': notif_doc.id,
            'message': notif_data.get('message'),
            'link': notif_data.get('link'),
            'timestamp': notif_data.get('timestamp'),
            'is_read': notif_data.get('is_read', False),
            'sender_name': notif_data.get('sender_name', 'System') # Default if sender_name isn't there
        })
        
    return render_template('notifications.html', notifications=user_notifications, active_page='notifications')


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