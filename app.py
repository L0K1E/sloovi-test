from flask import Flask, Response, jsonify, request
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import json_util
from bson.objectid import ObjectId
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'ThisIsADumbSecretKey'

client = MongoClient("mongodb+srv://logeshwaran:Bd434kvyE62P8w8t@sloovi.bf2efat.mongodb.net/?retryWrites=true&w=majority")
db = client.API

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        headers = request.headers
        bearer = headers.get('Authorization')    
        
        if bearer != None:
            token = bearer.split()[1]

        else:
            return jsonify({'message': 'Token not found / missing!'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            user = db.users.find_one({"email": data['email']})
            print(user)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token is expired !, Login again to get new token.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid !'}), 401

        return f(user, *args, **kwargs)
    return decorated 

# Register User
@app.route('/register', methods=['POST'])
def create_user():
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    email = request.json['email']
    password = request.json['password']

    if db.users.find_one({'email': email}):
        return jsonify({'message': 'email address is already taken'}), 401
    
    if first_name and last_name and email and password:
        hashed_pass = generate_password_hash(password)
        id = db.users.insert_one(
            {'first_name': first_name,'last_name': last_name,'email': email,'password': hashed_pass})  
        response = jsonify({
            'id': str(id),
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'pasword': hashed_pass
        })
        return response
    
    else:
        return not_found()

#login User
@app.route('/login', methods=['POST'])
def login_user():
    email = request.json['email']
    password = request.json['password']
    
    user = db.users.find_one({"email": email})
    
    if user and check_password_hash(user['password'], password):
        token = jwt.encode({'email': user['email'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'], algorithm="HS256")
        response = jsonify({
            "message": "Login successfull",
            "token": token
        })
        return response
    
    else:
        response = jsonify({
            "message": "Login Unsuccessfull. Kindly check your login credentials"
        })
        return response


#create template
@app.route('/template', methods=['POST'])
@login_required
def create_template(user):
    template_name = request.json['template_name']
    subject = request.json['subject']
    body = request.json['body']
    
    if template_name and subject and body:
        id = db.template.insert_one(
            {'user': user['email'],'template_name': template_name, 'subject': subject, 'body': body})  
        response = jsonify({
            'id': str(id),
            'user': user['email'],
            'template_name': template_name,
            'subject': subject,
            'body': body
        })
        return response
    else:
        return jsonify({"message": "Incorrect entries !"})
    


#List all template
@app.route('/template', methods=['GET'])
@login_required
def all_template(user):
    templates = db.template.find()
    response = json_util.dumps(templates)
    return Response(response, mimetype="application/json")

#Get single template
@app.route('/template/<id>', methods=['GET'])
@login_required
def get_template(id):
    template = db.template.find_one({'_id': ObjectId(id)})
    response = json_util.dumps(template)
    return Response(response, mimetype="application/json")

# Delete template
@app.route('/template/<id>', methods=['DELETE'])
@login_required
def delete_template(user, id):
    template = db.template.find_one({'_id': ObjectId(id)})
    if user['email'] == template['user']:
        db.template.delete_one({'_id': ObjectId(id)})
        response = jsonify({'message': 'Template '+ id + ' deleted successfully !'}), 200
        return response
    else:
        return jsonify({'message': 'Unauthorized Access !, Only user who created the template can delete it.'}), 401

#update template
@app.route('/template/<id>', methods=['PUT'])
@login_required
def update_template(user, id):
    template_name = request.json['template_name']
    subject = request.json['subject']
    body = request.json['body']

    template = db.template.find_one({'_id': ObjectId(id)})
    if user['email'] == template['user']:
        if template_name and subject and body:
            db.template.update_one({'_id': ObjectId(id)}, {'$set': {'template_name': template_name, 'subject': subject, 'body': body}})  
            response = jsonify({'message': 'Template '+ id + ' updated successfully !'}), 200
            return response
        else:
            return jsonify({"message": "Incorrect entries !"})
    else:
        return jsonify({'message': 'Unauthorized Access !, Only user who created the template can update it.'}), 401

@app.errorhandler(404)
def not_found(error=None):
    response = jsonify({
        'message' : 'Url not found: ' + request.url,
        'status': 404
    })
    response.status_code = 404
    return response
    
@app.route('/', methods=['GET'])
def home():
    return '''<h3>Flask REST api made for <b>Sloovi<b></h3>
              <p>/register, methods=[POST]</p>
              <p>/login, methods=[POST]</p>
              <p>/template, methods=[ GET, POST]</p>
              <p>/template/template_id, methods=[GET, PUT, DELETE]</p>
    '''

if __name__ == '__main__':
    app.run(debug=True)
