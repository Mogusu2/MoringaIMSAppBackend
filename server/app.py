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
from models import Role
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

@app.route('/roles', methods=['POST'])
def create_role():
    """Create a role (No JWT required)"""
    data = request.json

    if not data.get("name") or not data.get("permissions"):
        return jsonify({"error": "Role name and permissions are required"}), 400

    if Role.query.filter_by(name=data["name"]).first():
        return jsonify({"error": "Role already exists"}), 400

    new_role = Role(name=data["name"], permissions=data["permissions"])
    db.session.add(new_role)
    db.session.commit()

    return jsonify({"message": "Role created successfully", "role": {
        "id": str(new_role.id),
        "name": new_role.name,
        "permissions": new_role.permissions
    }}), 201


@app.route('/roles', methods=['GET'])
@jwt_required()
def get_roles():
    """Get all roles (Requires authentication)"""
    roles = Role.query.all()
    return jsonify([
        {"id": str(role.id), "name": role.name, "permissions": role.permissions}
        for role in roles
    ])


@app.route('/roles/<uuid:role_id>', methods=['GET'])
@jwt_required()
def get_role(role_id):
    """Get a single role by ID (Requires authentication)"""
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404
    return jsonify({"id": str(role.id), "name": role.name, "permissions": role.permissions})


@app.route('/roles/<uuid:role_id>', methods=['PUT'])
@jwt_required()
def update_role(role_id):
    """Update a role (Requires authentication & permissions)"""
    user = get_jwt_identity()
    if not check_permission(user["role"], "manage_roles"):
        return jsonify({"error": "Unauthorized"}), 403

    role = Role.query.get(role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    data = request.json
    role.name = data.get('name', role.name)
    role.permissions = data.get('permissions', role.permissions)
    db.session.commit()

    return jsonify({"message": "Role updated successfully"})


@app.route('/roles/<uuid:role_id>', methods=['DELETE'])
@jwt_required()
def delete_role(role_id):
    """Delete a role (Requires authentication & permissions)"""
    user = get_jwt_identity()
    if not check_permission(user["role"], "manage_roles"):
        return jsonify({"error": "Unauthorized"}), 403

    role = Role.query.get(role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    db.session.delete(role)
    db.session.commit()

    return jsonify({"message": "Role deleted successfully"})




@app.route('/register', methods=['POST'])
def register():
    data = request.json

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already exists"}), 400

    # Find role_id from the Role table
    role = Role.query.filter_by(name=data['role']).first()
    if not role:
        return jsonify({"error": "Invalid role"}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        role=role 
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



if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)
