from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
import firebase_admin
from functools import wraps
from firebase_admin import credentials, firestore, auth, storage
import uuid
import requests
from datetime import timedelta, datetime

# --- Your existing Firebase setup ( 그대로 유지 ) ---
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'pets-27b3a.firebasestorage.app' # Replace with your bucket name
})
db_firestore = firestore.client()
bucket = storage.bucket() # Make sure you have this if using Storage

app = Flask(__name__)
app.secret_key = 'lksdfsdfkjfneofweofskf9204392358342' # Change for production

FIREBASE_WEB_API_KEY = "AIzaSyDnMJOweajBQaCJ3MzJKomF-xYyYJJKkaU" # Store securely
FIREBASE_AUTH_SIGN_IN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"

app.permanent_session_lifetime = timedelta(days=30)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_uid' not in session:
            flash("You need to be logged in to view this page.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_unread_notification_count():
    if 'user_uid' in session:
        user_uid = session['user_uid']
        try:
            notifications_query = db_firestore.collection('notifications') \
                .where('recipient_uid', '==', user_uid) \
                .where('is_read', '==', False) \
                .stream()
            notifications = list(notifications_query)
            unread_count = len(notifications)
            unread_message_count = sum(1 for n in notifications
                                       if n.to_dict().get('type') == 'new_message')
            return dict(unread_notification_count=unread_count,
                        unread_message_count=unread_message_count)
        except Exception as e:
            print(f"Error fetching unread notification count: {e}")
            return dict(unread_notification_count=0, unread_message_count=0)
    return dict(unread_notification_count=0, unread_message_count=0)

def get_username(user_uid):
    if not user_uid: return 'Unknown User'
    try:
        user_doc = db_firestore.collection('users').document(user_uid).get()
        if user_doc.exists:
            return user_doc.to_dict().get('username', 'Unknown User')
    except Exception as e:
        print(f"Error fetching username for {user_uid}: {e}")
    return 'Unknown User'

# --- Your existing routes (home, profile, edit_profile, etc. 그대로 유지) ---
# Make sure view_profile_page is updated as in the previous detailed response to include friend_status
@app.route("/")
@login_required
def home():
    return render_template("home.html", active_page='home')

@app.route('/profile')
@login_required
def profile():
    user_uid = session.get('user_uid')
    username = get_username(user_uid)
    if username and username != 'Unknown User':
        return redirect(url_for('view_profile_page', view_username=username))
    else: # Fallback or prompt to edit profile if username is not set
        user_doc = db_firestore.collection('users').document(user_uid).get()
        if user_doc.exists and user_doc.to_dict().get('username'):
             return redirect(url_for('view_profile_page', view_username=user_doc.to_dict().get('username')))
        flash("Your username is not set or could not be found. Please edit your profile.", "warning")
        return redirect(url_for('edit_profile'))


@app.route('/profile/<string:view_username>')
@login_required
def view_profile_page(view_username):
    logged_in_user_uid = session.get('user_uid')
    users_ref = db_firestore.collection('users')
    user_query = users_ref.where('username', '==', view_username).limit(1).stream()
    target_user_doc = next(user_query, None)

    if not target_user_doc:
        flash(f"Profile for '{view_username}' not found.", "error")
        return redirect(url_for('home'))

    target_user_data = target_user_doc.to_dict()
    target_user_data['followers_count'] = target_user_data.get('followers_count', 0)
    target_user_data['following_count'] = target_user_data.get('following_count', 0)
    target_user_uid = target_user_doc.id
    is_own_profile = (target_user_uid == logged_in_user_uid)
    visibility = target_user_data.get('profile_visibility', 'private')
    
    # Friend Status Logic (ensure this is present and correct)
    friend_status = "not_friends"
    are_friends = logged_in_user_uid in target_user_data.get('friends', [])

    if are_friends:
        friend_status = "friends"
    elif not is_own_profile:
        outgoing_request_query = db_firestore.collection('friend_requests') \
            .where('fromUserId', '==', logged_in_user_uid) \
            .where('toUserId', '==', target_user_uid) \
            .where('status', '==', 'pending').limit(1).stream()
        if next(outgoing_request_query, None):
            friend_status = "request_sent"
        else:
            incoming_request_query = db_firestore.collection('friend_requests') \
                .where('fromUserId', '==', target_user_uid) \
                .where('toUserId', '==', logged_in_user_uid) \
                .where('status', '==', 'pending').limit(1).stream()
            incoming_request_doc = next(incoming_request_query, None)
            if incoming_request_doc:
                friend_status = "request_received"
                target_user_data['incoming_request_id'] = incoming_request_doc.id
    
    can_view_profile = visibility == 'public' or is_own_profile or are_friends # Friends can view private profiles

    return render_template("profile.html",
                           user=target_user_data,
                           is_own_profile=is_own_profile,
                           can_view_profile=can_view_profile,
                           friend_status=friend_status,
                           target_user_uid=target_user_uid,
                           active_page='profile')

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_uid = session.get('user_uid')
    user_ref = db_firestore.collection('users').document(user_uid)
    user_data = user_ref.get().to_dict() or {}

    auth_user = auth.get_user(user_uid)
    auth_email = auth_user.email
    
    if request.method == 'POST':
        # ... (rest of your edit_profile POST logic, ensure it includes profile_visibility)
        username = request.form.get('username')
        bio = request.form.get('bio')
        new_email = request.form.get('email') # Renamed to avoid conflict
        profile_visibility = request.form.get('profile_visibility', user_data.get('profile_visibility', 'private'))

        update_data = {}
        if username and username != user_data.get('username'):
            # Check if new username is taken
            existing_user = db_firestore.collection('users').where('username', '==', username).limit(1).stream()
            if next(existing_user, None) and get_username(user_uid) != username : # Check if it's not the current user's current username
                flash("Username already taken. Please choose a different one.", "error")
                return render_template('edit_profile.html', user=user_data, auth_email=auth_email, active_page='edit_profile')
            update_data['username'] = username
            if session.get('display_name') != username : # Update session display_name if username changes
                 session['display_name'] = username


        if bio is not None: update_data['bio'] = bio
        if new_email: update_data['email'] = new_email # Firestore email update
        update_data['profile_visibility'] = profile_visibility
        
        file = request.files.get('profile_image')
        if file and file.filename:
            try:
                blob = bucket.blob(f'profile_images/{user_uid}/{str(uuid.uuid4())}_{file.filename}')
                blob.upload_from_file(file, content_type=file.content_type)
                blob.make_public()
                update_data['profile_image'] = blob.public_url
            except Exception as e:
                flash(f"Error uploading profile image: {e}", "error")


        try: # Update Auth email
            if new_email and new_email != auth_email:
                auth.update_user(user_uid, email=new_email)
                session['user_email'] = new_email # Update session email
        except Exception as e:
            flash(f"Error updating email in Authentication: {str(e)}", "danger")
            return render_template('edit_profile.html', user=user_data, auth_email=auth_email, active_page='edit_profile')

        if update_data:
            user_ref.update(update_data)
            flash('Profile updated successfully!', 'success')
        else:
            flash('No changes to update.', 'info')
        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user_data, auth_email=auth_email, active_page='edit_profile')

# ... (logout, login, signup, search_users, direct_messages routes as before, ensure signup checks existing username)
@app.route('/edit_password', methods=['GET', 'POST'])
@login_required
def edit_password():
    # ... (your existing edit_password logic)
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
                return redirect(url_for('edit_profile')) # Or wherever appropriate
            except Exception as e:
                flash(f"Error updating password: {str(e)}", "danger")
    
    return render_template('edit_password.html') # Ensure this template exists

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (your existing login logic, ensure display_name is fetched/set in session)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # ... (rest of login logic)
        try:
            response = requests.post(FIREBASE_AUTH_SIGN_IN_URL, json={"email": email, "password": password, "returnSecureToken": True})
            response.raise_for_status() # Raise an exception for HTTP errors
            response_data = response.json()

            user_uid = response_data.get('localId')
            user_email = response_data.get('email')
            
            # Fetch username from Firestore to store as display_name
            display_name = get_username(user_uid) # Use our helper
            if display_name == 'Unknown User': # Fallback if Firestore fetch fails or no username
                auth_user = auth.get_user(user_uid)
                display_name = auth_user.display_name or user_email # Use Auth display_name or email

            session.clear()
            session['user_uid'] = user_uid
            session['user_email'] = user_email
            session['display_name'] = display_name 
            session.permanent = 'remember_me' in request.form
            
            next_url = request.args.get('next')
            return redirect(next_url or url_for('home'))

        except requests.exceptions.HTTPError as e:
            error_message = "Invalid email or password. Please try again." # Default
            if e.response is not None and e.response.json().get("error"):
                fb_error = e.response.json().get("error").get("message")
                if "INVALID_LOGIN_CREDENTIALS" in fb_error or "EMAIL_NOT_FOUND" in fb_error or "INVALID_PASSWORD" in fb_error :
                    error_message = "Invalid email or password. Please try again."
                else:
                    error_message = f"Login failed: {fb_error}"
            flash(error_message, "error")
            return redirect(url_for('login'))
        except requests.exceptions.RequestException as e:
            flash(f"Network error during login: {e}", "error")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
            return redirect(url_for('login'))
    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # ... (your existing signup logic, ensure it checks for existing username and stores initial friends list)
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash("All fields are required.", "error")
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash("Passwords don’t match.", "error")
            return redirect(url_for('signup'))

        # Check if username already exists in Firestore
        users_ref = db_firestore.collection('users')
        existing_user_query = users_ref.where('username', '==', username).limit(1).stream()
        if next(existing_user_query, None):
            flash("Username already taken. Please choose a different one.", "error")
            return redirect(url_for('signup'))
        
        try:
            user_record = auth.create_user(
                email=email,
                password=password,
                display_name=username # Set display name in Firebase Auth
            )
            user_data = {
                'username': username,
                'email': email,
                'created_at': firestore.SERVER_TIMESTAMP,
                'profile_visibility': 'private',
                'friends': [],  # Initialize empty friends list
                'followers_count': 0,
                'following_count': 0
            }
            db_firestore.collection('users').document(user_record.uid).set(user_data)

            session.clear()
            session['user_uid'] = user_record.uid
            session['user_email'] = email
            session['display_name'] = username

            flash(f"Welcome, {username}! Your account has been created.", "success")
            return redirect(url_for('home'))

        except firebase_admin.auth.EmailAlreadyExistsError:
            flash("This email address is already in use.", "error")
            return redirect(url_for('signup'))
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
            return redirect(url_for('signup'))
    return render_template("signup.html", active_page='signup')

@app.route('/search_users', methods=['GET'])
@login_required
def search_users():
    # ... (your existing search_users logic)
    query = request.args.get('q', '').strip().lower()
    logged_in_user_uid = session.get('user_uid')

    if not query: return jsonify([])
    
    users_stream = db_firestore.collection('users').stream() # Less efficient for large DBs
    results = []
    for user_doc in users_stream:
        if user_doc.id == logged_in_user_uid: continue # Skip self
        user_data = user_doc.to_dict()
        username_lower = user_data.get('username', '').lower()
        if query in username_lower:
            results.append({
                'id': user_doc.id,
                'username': user_data.get('username'),
                'profile_image': user_data.get('profile_image', url_for('static', filename='images/default_avatar.png'))
            })
            if len(results) >= 10: break # Limit results
    return jsonify(results)


def get_or_create_conversation(uid1, uid2):
    """Return a consistent conversation id for two users and ensure document exists."""
    sorted_ids = sorted([uid1, uid2])
    conv_id = f"{sorted_ids[0]}_{sorted_ids[1]}"
    conv_ref = db_firestore.collection('conversations').document(conv_id)
    conv_ref.set({'participants': sorted_ids}, merge=True)
    return conv_id


@app.route('/start_conversation/<string:target_uid>')
@login_required
def start_conversation(target_uid):
    user_uid = session.get('user_uid')
    conv_id = get_or_create_conversation(user_uid, target_uid)
    return redirect(url_for('direct_messages', conversation_id=conv_id))


@app.route('/messages', methods=['GET'])
@login_required
def messages_home():
    """Simple page to search friends and start conversations."""
    user_uid = session.get('user_uid')
    user_doc = db_firestore.collection('users').document(user_uid).get()
    friend_ids = user_doc.to_dict().get('friends', []) if user_doc.exists else []
    friends = []
    for f_uid in friend_ids:
        doc = db_firestore.collection('users').document(f_uid).get()
        if doc.exists:
            data = doc.to_dict()
            friends.append({'uid': f_uid, 'username': data.get('username')})

    query = request.args.get('q', '').strip().lower()
    if query:
        friends = [f for f in friends if query in f['username'].lower()]

    return render_template('messages_home.html', friends=friends, query=query, active_page='messages')


@app.route('/direct_messages/<conversation_id>', methods=['GET', 'POST'])
@login_required
def direct_messages(conversation_id):
    messages_ref = db_firestore.collection('conversations').document(conversation_id).collection('messages')
    current_uid = session.get('user_uid')

    # Mark message notifications for this conversation as read
    notif_query = db_firestore.collection('notifications') \
        .where('recipient_uid', '==', current_uid) \
        .where('type', '==', 'new_message') \
        .where('conversation_id', '==', conversation_id) \
        .where('is_read', '==', False) \
        .stream()
    for doc in notif_query:
        doc.reference.update({'is_read': True})

    if request.method == 'POST' and 'message' in request.form:
        sender_name = session.get('display_name', 'Anonymous')
        sender_uid = current_uid
        text = request.form.get('message')
        if text:
            messages_ref.add({
                'sender_name': sender_name,
                'sender_uid': sender_uid,
                'text': text,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            # Notify other participants
            conv_doc = db_firestore.collection('conversations').document(conversation_id).get()
            participants = conv_doc.to_dict().get('participants', []) if conv_doc.exists else []
            for uid in participants:
                if uid != sender_uid:
                    db_firestore.collection('notifications').add({
                        'recipient_uid': uid,
                        'sender_uid': sender_uid,
                        'sender_name': sender_name,
                        'message': f"{sender_name} sent you a message.",
                        'link': url_for('direct_messages', conversation_id=conversation_id),
                        'type': 'new_message',
                        'conversation_id': conversation_id,
                        'is_read': False,
                        'timestamp': firestore.SERVER_TIMESTAMP
                    })
        return redirect(url_for('direct_messages', conversation_id=conversation_id))

    messages_query = messages_ref.order_by('timestamp', direction=firestore.Query.ASCENDING).stream()
    message_list = [{'id': m.id, **m.to_dict()} for m in messages_query]
    return render_template('direct_messages.html', messages=message_list, conversation_id=conversation_id)


@app.route('/edit_message/<conversation_id>/<message_id>', methods=['POST'])
@login_required
def edit_message(conversation_id, message_id):
    new_text = request.form.get('new_text', '').strip()
    msg_ref = db_firestore.collection('conversations').document(conversation_id).collection('messages').document(message_id)
    msg_doc = msg_ref.get()
    if msg_doc.exists and msg_doc.to_dict().get('sender_uid') == session.get('user_uid') and new_text:
        msg_ref.update({'text': new_text, 'edited': True})
    return redirect(url_for('direct_messages', conversation_id=conversation_id))


@app.route('/delete_message/<conversation_id>/<message_id>', methods=['POST'])
@login_required
def delete_message(conversation_id, message_id):
    msg_ref = db_firestore.collection('conversations').document(conversation_id).collection('messages').document(message_id)
    msg_doc = msg_ref.get()
    if msg_doc.exists and msg_doc.to_dict().get('sender_uid') == session.get('user_uid'):
        msg_ref.delete()
    return redirect(url_for('direct_messages', conversation_id=conversation_id))


# --- Friend Request Routes ---
@app.route('/send_friend_request/<string:recipient_uid>', methods=['POST'])
@login_required
def send_friend_request(recipient_uid):
    sender_uid = session['user_uid']
    sender_username = session.get('display_name', get_username(sender_uid)) # Use session display_name first
    recipient_username = get_username(recipient_uid)

    if sender_uid == recipient_uid:
        flash("You cannot send a friend request to yourself.", "error")
        return redirect(request.referrer or url_for('home'))

    # Check if already friends or request pending (as in previous response)
    # ... (add checks here for existing friendship or pending request to prevent duplicates)
    # For brevity, assuming checks from previous response are in place. If not, add them:
    sender_doc_snap = db_firestore.collection('users').document(sender_uid).get()
    if sender_doc_snap.exists and recipient_uid in sender_doc_snap.to_dict().get('friends', []):
        flash(f"You are already friends with {recipient_username}.", "info")
        return redirect(request.referrer or url_for('view_profile_page', view_username=recipient_username))

    # Check for existing pending request (either way)
    req_query_outgoing = db_firestore.collection('friend_requests') \
        .where('fromUserId', '==', sender_uid) \
        .where('toUserId', '==', recipient_uid) \
        .where('status', '==', 'pending').limit(1).stream()
    req_query_incoming = db_firestore.collection('friend_requests') \
        .where('fromUserId', '==', recipient_uid) \
        .where('toUserId', '==', sender_uid) \
        .where('status', '==', 'pending').limit(1).stream()

    if next(req_query_outgoing, None) or next(req_query_incoming, None):
        flash("A friend request is already pending or you've already sent one.", "info")
        return redirect(request.referrer or url_for('view_profile_page', view_username=recipient_username))


    try:
        request_doc_ref = db_firestore.collection('friend_requests').document()
        request_id = request_doc_ref.id
        
        request_doc_ref.set({
            'fromUserId': sender_uid,
            'fromUsername': sender_username,
            'toUserId': recipient_uid,
            'toUsername': recipient_username,
            'status': 'pending',
            'timestamp': firestore.SERVER_TIMESTAMP
        })

        db_firestore.collection('notifications').add({
            'recipient_uid': recipient_uid,
            'sender_uid': sender_uid,
            'sender_name': sender_username,
            'message': f"{sender_username} sent you a friend request.",
            'link': url_for('view_profile_page', view_username=sender_username), # Link to sender's profile
            'type': 'friend_request',
            'request_id': request_id,
            'is_read': False,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        flash(f"Friend request sent to {recipient_username}.", "success")
    except Exception as e:
        flash(f"Error sending friend request: {e}", "error")
    
    return redirect(request.referrer or url_for('view_profile_page', view_username=recipient_username))


@app.route('/handle_friend_request/<string:request_id>/<string:action>', methods=['POST'])
@login_required
def handle_friend_request(request_id, action):
    user_uid = session['user_uid']
    current_username = session.get('display_name', get_username(user_uid))
    
    request_ref = db_firestore.collection('friend_requests').document(request_id)
    request_doc = request_ref.get()

    if not request_doc.exists:
        flash("Friend request not found.", "error")
        return redirect(request.form.get('next_url') or url_for('notifications_page'))

    request_data = request_doc.to_dict()
    if request_data.get('toUserId') != user_uid:
        flash("You are not authorized to act on this request.", "error")
        return redirect(request.form.get('next_url') or url_for('notifications_page'))
    
    if request_data.get('status') != 'pending':
        flash("This request has already been actioned.", "info")
        return redirect(request.form.get('next_url') or url_for('notifications_page'))

    sender_uid = request_data.get('fromUserId')
    sender_username = request_data.get('fromUsername', get_username(sender_uid))

    try:
        if action == 'accept':
            request_ref.update({'status': 'accepted', 'responded_at': firestore.SERVER_TIMESTAMP})

            user_ref = db_firestore.collection('users').document(user_uid)
            sender_ref = db_firestore.collection('users').document(sender_uid)

            # Fetch current counts to ensure they exist before incrementing
            user_data = user_ref.get().to_dict() or {}
            sender_data = sender_ref.get().to_dict() or {}

            batch = db_firestore.batch()
            batch.update(user_ref, {
                'friends': firestore.ArrayUnion([sender_uid]),
                'followers_count': user_data.get('followers_count', 0) + 1,
                'following_count': user_data.get('following_count', 0) + 1
            })
            batch.update(sender_ref, {
                'friends': firestore.ArrayUnion([user_uid]),
                'followers_count': sender_data.get('followers_count', 0) + 1,
                'following_count': sender_data.get('following_count', 0) + 1
            })
            batch.commit()

            db_firestore.collection('notifications').add({
                'recipient_uid': sender_uid,
                'sender_uid': user_uid,
                'sender_name': current_username,
                'message': f"{current_username} accepted your friend request.",
                'link': url_for('view_profile_page', view_username=current_username),
                'type': 'friend_request_accepted',
                'is_read': False,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            flash(f"You are now friends with {sender_username}!", "success")

        elif action == 'decline':
            request_ref.update({'status': 'declined', 'responded_at': firestore.SERVER_TIMESTAMP})
            # No notification for decline to keep things simpler/less negative
            flash(f"Friend request from {sender_username} declined.", "info")
        
        # Mark the original friend_request notification as read
        if action in ['accept', 'decline']:
            notif_query = db_firestore.collection('notifications') \
                .where('request_id', '==', request_id) \
                .where('recipient_uid', '==', user_uid) \
                .where('type', '==', 'friend_request') \
                .limit(1).stream()
            for notif_doc_to_update in notif_query:
                notif_doc_to_update.reference.update({'is_read': True})
                
    except Exception as e:
        flash(f"Error handling friend request: {e}", "error")

    return redirect(request.form.get('next_url') or request.referrer or url_for('notifications_page'))

@app.route('/unfriend/<string:friend_uid>', methods=['POST'])
@login_required
def unfriend(friend_uid):
    """Remove a user from the current user's friends list."""
    user_uid = session['user_uid']

    user_ref = db_firestore.collection('users').document(user_uid)
    friend_ref = db_firestore.collection('users').document(friend_uid)

    user_doc = user_ref.get()
    if not user_doc.exists or friend_uid not in user_doc.to_dict().get('friends', []):
        flash("User is not in your friends list.", "error")
        return redirect(request.referrer or url_for('home'))

    friend_username = get_username(friend_uid)

    try:
        batch = db_firestore.batch()

        user_updates = {'friends': firestore.ArrayRemove([friend_uid])}
        friend_updates = {'friends': firestore.ArrayRemove([user_uid])}

        user_data = user_doc.to_dict() or {}
        friend_data = friend_ref.get().to_dict() or {}

        # Decrement follower/following counts based on existing values
        user_updates['followers_count'] = max(user_data.get('followers_count', 1) - 1, 0)
        user_updates['following_count'] = max(user_data.get('following_count', 1) - 1, 0)
        friend_updates['followers_count'] = max(friend_data.get('followers_count', 1) - 1, 0)
        friend_updates['following_count'] = max(friend_data.get('following_count', 1) - 1, 0)

        batch.update(user_ref, user_updates)
        batch.update(friend_ref, friend_updates)
        batch.commit()
        flash(f"You are no longer friends with {friend_username}.", "info")
    except Exception as e:
        flash(f"Error removing friend: {e}", "error")

    return redirect(url_for('view_profile_page', view_username=friend_username))

# --- Removed friend_requests_page route as it's no longer needed ---

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
            'link': notif_data.get('link', '#'),
            'timestamp': notif_data.get('timestamp'), # Jinja will handle Firestore Timestamp
            'is_read': notif_data.get('is_read', False),
            'sender_name': notif_data.get('sender_name', 'System'),
            'type': notif_data.get('type'),
            'request_id': notif_data.get('request_id') # Ensure request_id is passed
        })
    return render_template('notifications.html', notifications=user_notifications, active_page='notifications')


@app.route('/api/notifications')
@login_required
def notifications_api():
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
            'link': notif_data.get('link', '#'),
            'timestamp': notif_data.get('timestamp').isoformat() if notif_data.get('timestamp') else None,
            'is_read': notif_data.get('is_read', False),
            'sender_name': notif_data.get('sender_name', 'System'),
            'type': notif_data.get('type')
        })
    return jsonify(user_notifications)

@app.route('/mark_notification_as_read/<string:notification_id>', methods=['POST']) # Changed to POST
@login_required
def mark_notification_as_read(notification_id):
    user_uid = session['user_uid']
    notif_ref = db_firestore.collection('notifications').document(notification_id)
    notif_doc = notif_ref.get()

    if notif_doc.exists and notif_doc.to_dict().get('recipient_uid') == user_uid:
        notif_ref.update({'is_read': True})
    else:
        flash("Notification not found or access denied.", "error")
    
    return redirect(request.form.get('next_url') or request.referrer or url_for('notifications_page'))


@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    user_uid = session['user_uid']
    try:
        query = db_firestore.collection('notifications') \
            .where('recipient_uid', '==', user_uid) \
            .where('is_read', '==', False) \
            .stream()
        batch = db_firestore.batch()
        for doc in query:
            batch.update(doc.reference, {'is_read': True})
        batch.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error clearing notifications: {e}")
        return jsonify({'status': 'error'}), 500


@app.route("/test-firebase") # Keep for testing
def test_firebase():
    try:
        doc_ref = db_firestore.collection(u'test').document(u'connection')
        doc_ref.set({u'connected': True})
        return "Firebase Firestore write succeeded!"
    except Exception as e:
        return f"Firebase Firestore write failed: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)
