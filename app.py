from flask import Flask, render_template
import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db_firestore = firestore.client()

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("home.html", active_page='home')


@app.route('/profile')
def profile():
    return render_template("profile.html", active_page='profile')


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/signup')
def signup():
    return render_template("signup.html")


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