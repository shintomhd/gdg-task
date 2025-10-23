from flask import Flask, request, jsonify
import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from flask_migrate import Migrate
from hashlib import sha256
from flask_jwt_extended import JWTManager, get_jwt, get_jwt_identity, jwt_required, create_access_token
from dotenv import load_dotenv
from datetime import datetime
import random
from flask_mail import Mail, Message
from flasgger import Swagger

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'abc123')
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'abc123')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
# Building and designing the database
# Sorry I didn't get enough time to change the Sql db to Postgres :(
# print(app.config)

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(app, model_class=Base)
migrate = Migrate(app, db)
jwt = JWTManager(app)
mail = Mail(app)
swagger = Swagger(app, template_file='swagger.yaml')

class User(db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(db.String, nullable=False, unique=True)
    password: Mapped[str] = mapped_column(db.String, nullable=False)
    email: Mapped[str] = mapped_column(db.String, nullable=False, unique=True)
    otp: Mapped[int] = mapped_column(db.Integer, nullable=True)

class Speaker(db.Model):
    __tablename__ = 'speakers'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(db.String, nullable=False, unique=True)
    password: Mapped[str] = mapped_column(db.String, nullable=False)
    email: Mapped[str] = mapped_column(db.String, nullable=False)
    expertise: Mapped[str] = mapped_column(db.String, nullable=False)
    price_per_session: Mapped[str] = mapped_column(db.Integer, nullable=False)
    otp: Mapped[int] = mapped_column(db.Integer, nullable=True)

class Session(db.Model):
    __tablename__ = 'sessions'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True, autoincrement=True)
    speaker_id: Mapped[int] = mapped_column(db.Integer, db.ForeignKey('speakers.id'))
    user_id: Mapped[int] = mapped_column(db.Integer, db.ForeignKey('users.id'))
    start_time: Mapped[str] = mapped_column(db.String, nullable=True)

with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    return jsonify({'message':'Navigate to /apidocs to get started'}),200

@app.route('/api/user/register', methods=['POST'])
def register_user():
    if request.is_json:
        data = request.get_json()
        data = dict(data)
        if 'username' not in data or 'password' not in data or 'email' not in data:
            return jsonify({'error':'Please specify the username, password and email in JSON'}), 400
        exists_username = db.session.query(db.session.query(User).filter_by(username=data['username']).exists()).scalar()
        exists_email = db.session.query(db.session.query(User).filter_by(email=data['email']).exists()).scalar()
        if exists_username or exists_email:
            return jsonify({'error': 'username or email already exists!!'}), 409
        user = User(username=data['username'], email=data['email'], password=sha256(data['password'].encode()).hexdigest())
        db.session.add(user)
        db.session.commit()
        return jsonify({'success':True}), 200
    else:
        return jsonify({"error":"Invalid content"}), 400

@app.route('/api/speaker/register', methods=['POST'])
def register_speaker():
    if request.is_json:
        data = request.get_json()
        data = dict(data)
        if 'username' not in data or 'password' not in data or 'email' not in data or 'expertise' not in data or 'price_per_session' not in data:
            return jsonify({'error':'Please specify the username, password, expertise, price_per_session and email in JSON'}), 400
        exists_username = db.session.query(db.session.query(Speaker).filter_by(username=data['username']).exists()).scalar()
        exists_email = db.session.query(db.session.query(Speaker).filter_by(email=data['email']).exists()).scalar()
        if exists_username or exists_email:
            return jsonify({'error': 'username or email already exists!!'}), 409
        speaker = Speaker(username=data['username'], email=data['email'], password=sha256(data['password'].encode()).hexdigest(), expertise=data['expertise'], price_per_session=int(data['price_per_session']))
        db.session.add(speaker)
        db.session.commit()
        return jsonify({'success': True}), 200
    else:
        return jsonify({"error":"Invalid content"}), 400


@app.route('/api/user/login', methods=['POST'])
def login_user():
    if request.is_json:
        data = dict(request.get_json())
        exists_username = db.session.query(db.session.query(User).filter_by(username=data['username']).exists()).scalar()
        exists_email = db.session.query(db.session.query(User).filter_by(email=data['email']).exists()).scalar()
        pass_hash = sha256(data['password'].encode()).hexdigest()
        if not exists_email or not exists_username:
            return jsonify({"error":"The given credentials don't exist"}), 401
        user = User.query.filter_by(username=data['username']).first()
        if user.password != pass_hash:
            return jsonify({"error": "Invalid username or password"}), 401
        additional_claims = {"role":"none"}
        access_token = create_access_token(identity=data['username'], additional_claims=additional_claims)
        user.otp = random.randint(100000, 999999)
        db.session.commit()
        return jsonify({"success":True, "access_token":access_token}), 200
    else:
        return jsonify({"error":"Invalid content"}), 400


@app.route('/api/speaker/login', methods=['POST'])
def login_speaker():
    if request.is_json:
        data = dict(request.get_json())
        exists_username = db.session.query(db.session.query(Speaker).filter_by(username=data['username']).exists()).scalar()
        exists_email = db.session.query(db.session.query(Speaker).filter_by(email=data['email']).exists()).scalar()
        pass_hash = sha256(data['password'].encode()).hexdigest()
        if not exists_email or not exists_username:
            return jsonify({"error":"The given credentials don't exist"}), 401
        speaker = Speaker.query.filter_by(username=data['username']).first()
        if speaker.password != pass_hash:
            return jsonify({"error": "Invalid username or password"}), 401
        additional_claims = {"role":"none"}
        access_token = create_access_token(identity=data['username'], additional_claims=additional_claims)
        speaker.otp = random.randint(100000, 999999)
        db.session.commit()
        return jsonify({"success":True, "access_token":access_token}), 200
    else:
        return jsonify({"error":"Invalid content"}), 400

@app.route("/api/user/verify_otp", methods=['GET','POST'])
@jwt_required()
def verify_user_otp():
    user_identity = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] != 'none':
        return jsonify({"message":"user is already verified"}), 409
    user_profile = User.query.filter_by(username=user_identity).first()
    otp = user_profile.otp
    if request.method == 'GET':
        msg = Message(subject='OTP Verification', sender=app.config['MAIL_USERNAME'], recipients=[user_profile.email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        return jsonify({"message":"OTP sent successfully"}), 200
    if request.method == 'POST':
        if request.is_json:
            data = dict(request.get_json())
            if 'otp' not in data:
                return jsonify({"error":"Please specify otp"}), 400
            if data['otp'] == otp:
                additional_claims = {"role":"user"}
                access_token = create_access_token(identity=user_profile.username, additional_claims=additional_claims)
                user_profile.otp = None
                db.session.commit()
                return jsonify({"success":True, "access_token":access_token}), 200

@app.route("/api/speaker/verify_otp", methods=['GET','POST'])
@jwt_required()
def verify_speaker_otp():
    user_identity = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] != 'none':
        return jsonify({"message":"user is already verified"}), 409
    user_profile = Speaker.query.filter_by(username=user_identity).first()
    otp = user_profile.otp
    if request.method == 'GET':
        msg = Message(subject='OTP Verification', sender=app.config['MAIL_USERNAME'], recipients=[user_profile.email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        return jsonify({"message":"OTP sent successfully"}), 200
    if request.method == 'POST':
        if request.is_json:
            data = dict(request.get_json())
            if 'otp' not in data:
                return jsonify({"error":"Please specify otp"}), 400
            if data['otp'] == otp:
                additional_claims = {"role":"speaker"}
                access_token = create_access_token(identity=user_profile.username, additional_claims=additional_claims)
                user_profile.otp = None
                db.session.commit()
                return jsonify({"success":True, "access_token":access_token}), 200

# https://flask-jwt-extended.readthedocs.io/en/stable/add_custom_data_claims.html allows me to check the role and shi
@app.route('/api/user/profile')
@jwt_required()
def user_profile():
    user = get_jwt_identity()
    claims = get_jwt()
    if claims['role'] != 'user':
        return jsonify({'error': 'Not a user'}), 401
    user_profile = User.query.filter_by(username=user).first()
    return jsonify({'username': user_profile.username, 'email': user_profile.email}), 200

@app.route('/api/speaker/profile')
@jwt_required()
def speaker_profile():
    speaker = get_jwt_identity()
    claims = get_jwt()
    speaker_profile = Speaker.query.filter_by(username=speaker).first()
    if claims['role'] != 'speaker':
        return jsonify({'error': 'Not a speaker'}), 401
    return jsonify({'username': speaker_profile.username, 'email': speaker_profile.email, 'expertise': speaker_profile.expertise, 'price_per_session': speaker_profile.price_per_session}), 200

# Session Booking: Once a slot is booked, it can't be booked in by another user, schedule a calendar event or smth and send an email when the process is done
@app.route('/api/book_session', methods=['POST'])
@jwt_required()
def book_session():
    claims = get_jwt()
    if claims['role'] != 'user':
        return jsonify({'error': 'Only users can book sessions'}), 403

    data = request.get_json()
    if not data or 'speaker_id' not in data or 'start_time' not in data:
        return jsonify({'error': 'Please provide speaker_id and start_time in ISO format'}), 400

    try:
        start_time = datetime.fromisoformat(data['start_time'])
    except ValueError:
        return jsonify({'error': 'Invalid datetime format. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400

    # Only allow 9AM to 4PM sessions
    if start_time.minute != 0 or not (9 <= start_time.hour <= 15):
        return jsonify({'error': 'Session must start on the hour between 09:00 and 15:00'}), 400

    # Check for slot collision
    existing_session = Session.query.filter_by(
        speaker_id=data['speaker_id'],
        start_time=start_time.isoformat()
    ).first()

    if existing_session:
        return jsonify({'error': 'This time slot is already booked'}), 409

    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Book session
    new_session = Session(
        speaker_id=data['speaker_id'],
        user_id=user.id,
        start_time=start_time.isoformat()
    )
    db.session.add(new_session)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Session booked successfully'}), 200

if __name__=="__main__":
    app.run(debug=True, host='0.0.0.0')

#TODO: Remove the admin panel during production (or add some sort of admin authentication)
