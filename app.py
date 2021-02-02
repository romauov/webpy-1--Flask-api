import config
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps




app = Flask(__name__)
app.config.from_mapping(SQLALCHEMY_DATABASE_URI=config.POSTGRE_URI)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Advt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    text = db.Column(db.String(200))
    pub_date = db.Column(db.DateTime, nullable=False,
                         default=datetime.date.today())

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                         nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'token' in request.headers:
            token = request.headers['token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, "secret_key", algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'No rights perform that action!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'No rights perform that action!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])

def create_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'No rights perform that action!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'No rights perform that action!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, "secret_key", algorithm='HS256')

        return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/advt', methods=['GET'])
@token_required
def get_all_ads(current_user):
    advts = Advt.query.filter_by(owner_id=current_user.id).all()
    output = []

    for advt in advts:
        advt_data = {}
        advt_data['id'] = advt.id
        advt_data['title'] = advt.title
        advt_data['text'] = advt.text
        advt_data['pub_date'] = advt.pub_date
        output.append(advt_data)

    return jsonify({'advts': output})

@app.route('/advt/<advt_id>', methods=['GET'])
@token_required
def get_one_ad(current_user, advt_id):
    advt = Advt.query.filter_by(id=advt_id, owner_id=current_user.id).first()

    if not advt:
        return jsonify({'message' : 'No todo found!'})

    advt_data = {}
    advt_data['id'] = advt.id
    advt_data['title'] = advt.title
    advt_data['text'] = advt.text
    advt_data['pub_date'] = advt.pub_date

    return jsonify(advt_data)

@app.route('/advt', methods=['POST'])
@token_required
def create_advt(current_user):
    data = request.get_json()

    new_advt = Advt(text=data['text'], title=data['title'], owner_id=current_user.id)
    db.session.add(new_advt)
    db.session.commit()

    return jsonify({'message': "Ad created!"})

@app.route('/advt/<advt_id>', methods=['PUT'])
@token_required
def update_advt(current_user, advt_id):
    data = request.get_json()
    advt = Advt.query.filter_by(id=advt_id, owner_id=current_user.id).first()

    if not advt:
        return jsonify({'message': 'No Ad found!'})

    advt.title = data['title']
    advt.text = data['text']

    db.session.commit()

    return jsonify({'message': 'Ad has been modified!'})

@app.route('/advt/<advt_id>', methods=['DELETE'])
@token_required
def delete_advt(current_user, advt_id):
    advt = Advt.query.filter_by(id=advt_id, owner_id=current_user.id).first()

    if not advt:
        return jsonify({'message': 'No ad found!'})

    db.session.delete(advt)
    db.session.commit()

    return jsonify({'message': 'Ad deleted!'})
