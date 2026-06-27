from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from Models.extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from Models.user import User
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_NAME')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()
    print("Database tables verified/created successfully.")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt_token')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid email or password'}), 401

        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.now(timezone.utc) + timedelta(hours=1)}, 
                           app.config['SECRET_KEY'], algorithm="HS256")

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie('jwt_token', token)

        return response

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'User already exists. Please login.'}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(public_id=str(uuid.uuid4()), name=name, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@token_required
def dashboard(current_user):
    return f"<h1>Welcome {current_user.name}! You are logged in.</h1>"

if __name__ == '__main__':   
    app.run(debug=True)