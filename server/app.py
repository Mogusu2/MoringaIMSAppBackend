from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from config import Config
from models import db, User, Inventory, Notification
from permissions import ROLES_PERMISSIONS
from dotenv import load_dotenv
import os

load_dotenv()

# Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Extensions
db.init_app(app) 
migrate = Migrate(app, db) 
jwt = JWTManager(app)

# Authentication Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 400
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        username=data['username'], 
        password=hashed_password, 
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(
            identity={"id": user.id, "username": user.username, "role": user.role}, 
            expires_delta=timedelta(hours=1)
        )
        return jsonify(access_token=access_token)
    return jsonify({"error": "Invalid credentials"}), 401

# Role-Based Access Control
def check_permission(user_role, required_permission):
    return required_permission in ROLES_PERMISSIONS.get(user_role, [])

# Inventory Routes
@app.route('/inventory', methods=['GET'])
@jwt_required()
def get_inventory():
    user = get_jwt_identity()
    if not check_permission(user["role"], "inventory"):
        return jsonify({"error": "Unauthorized"}), 403
    inventory = Inventory.query.all()
    return jsonify([
        {"id": item.id, "name": item.name, "barcode": item.barcode, "quantity": item.quantity}
        for item in inventory
    ])

@app.route('/inventory', methods=['POST'])
@jwt_required()
def add_inventory():
    user = get_jwt_identity()
    if not check_permission(user["role"], "inventory"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    new_item = Inventory(name=data['name'], barcode=data['barcode'], quantity=data['quantity'])
    db.session.add(new_item)
    db.session.commit()
    return jsonify({"message": "Item added to inventory"}), 201

# Barcode Scanning Endpoint
@app.route('/scan', methods=['POST'])
@jwt_required()
def scan_barcode():
    user = get_jwt_identity()
    data = request.json
    item = Inventory.query.filter_by(barcode=data['barcode']).first()
    if item:
        return jsonify({"message": f"Scanned item: {item.name}", "quantity": item.quantity})
    return jsonify({"error": "Item not found"}), 404

# Notifications
@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user["id"]).all()
    return jsonify([
        {"id": note.id, "message": note.message} 
        for note in notifications
    ])

# Run the App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure database tables exist
    app.run(debug=True)
