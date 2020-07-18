from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

import bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data-dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JSON_SORT_KEYS"] = False

app.config['JWT_SECRET_KEY'] = 'segredo'
jwt = JWTManager(app)

db = SQLAlchemy(app)

class User(db.Model):

    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), unique=True, nullable=False)
    idade = db.Column(db.Integer, default=0)
    
    password_hash = db.Column(db.String(128), nullable = False)

    def json(self):
        user_json = {'id': self.id,
                     'name': self.name,
                     'email': self.email,
                     'idade': self.idade}
        return user_json


@app.route('/users/', methods=['POST'])
def create():

    data = request.json
    name = data.get('name')
    email = data.get('email')
    idade = data.get('idade')
    password = data.get('password')
    
    if not name or not email or not password:

        return {'error': 'Dados insuficientes'}, 400

    user_check = User.query.filter_by(email=email).first()

    if user_check:
      return {'error':'Email já cadastrado'}, 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt() )

    user = User(name=name, email=email, idade=idade, password_hash=password_hash)

    db.session.add(user)
    db.session.commit()

    return user.json(), 200


@app.route('/users/', methods=['GET'])
def index():
    data = request.args
    idade = data.get('idade')  

    if not idade:  
        users = User.query.all()  
    else:
        idade = idade.split('-')
        if len(idade) == 1:
            users = User.query.filter_by(idade=idade[0])
        else:
            users = User.query.filter(
                db.and_(User.idade >= idade[0], User.idade <= idade[1]))

    return jsonify([user.json() for user in users]), 200




#---------------------------SISTEMA DE LOGIN E AUTENTIFICAÇÃO---------------------------------

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Faltando JSON"}), 400

    data = request.json

    email = data.get('email', None)
    password = data.get('password', None)

    if not email:
        return jsonify({"msg": "Insira o email"}), 400
    if not password:
        return jsonify({"msg": "Insira a senha"}), 400
      
    user_check = User.query.filter_by(email=email).first() # Vê se o email inserido é algum existente no banco de dados
    if not user_check:
      return 'Email não cadastrado'

    if bcrypt.checkpw(password.encode(), user_check.password_hash):
      print("It Matches!")
      access_token = create_access_token(identity=email)
      return jsonify(access_token=access_token), 20

    else:
     return 'Senha incorreta', 400

#Autenticar
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
  current_user = get_jwt_identity()
  return jsonify(logged_in_as=current_user), 200



@app.route('/users/<int:id>', methods=['GET', 'PUT', 'PATCH', 'DELETE']) # AQUI COMEÇA A ENTREGA 1
def user_detail(id):

  user = User.query.get_or_404(id)

  if request.method == 'GET': #----- USANDO O GET
    return user.json(), 200

  if request.method == 'PUT':

    data = request.json

    if not data:
      return {'error': 'Requisição precisa de body'}, 400

    name = data.get('name')
    email = data.get('email')

    if not name or not email:
      return {'error':'Dados insuficientes'}, 400
    
    if User.query.filter_by(email=email).first() and email != user.email:
            return {'error': 'Email já cadastrado'}, 400
    
    user.name = name
    user.email = email

    db.session.add(user)
    db.session.commit()

    return user.json(),200


  if request.method == 'PATCH':
    data = request.json

    if not data:
      return {'error': 'Requisição pricisa de body'}, 400

    email = data.get('email')

    if User.query.filter_by(email=email).first() and email != user.email:
      return {'error': 'Email já cadastrado'}, 400

    user.name = data.get('name', user.name)
    user.email = data.get('email', user.email)
    user.idade = data.get('idade', user.idade)

    db.session.add(user)
    db.session.commit()

    return user.json(), 200


  if request.method == 'DELETE':
    db.session.delete(user)
    db.session.commit()
    return {}, 204
      

if __name__ == '__main__':
    app.run(debug=True)