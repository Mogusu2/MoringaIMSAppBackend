from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.event import listen
import uuid
from datetime import datetime

db = SQLAlchemy()


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.Column(JSON, nullable=False)

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey('roles.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

    def __repr__(self):
        return f"<User {self.name} - {self.email}>"


class Inventory(db.Model):
    __tablename__ = 'inventory'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_name = db.Column(db.String(255), nullable=False)
    barcode = db.Column(db.String(100), unique=True, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

    def __repr__(self):
        return f"<Inventory {self.item_name} - {self.barcode}>"



class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(255), nullable=False)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False, default="available")

    def __repr__(self):
        return f"<Asset {self.name} - {self.serial_number}>"




class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    item_id = db.Column(UUID(as_uuid=True), db.ForeignKey('inventory.id'), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # "borrow" or "return"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('transactions', lazy=True))
    item = db.relationship('Inventory', backref=db.backref('transactions', lazy=True))

    def __repr__(self):
        return f"<Transaction {self.action} - {self.user_id} - {self.item_id}>"



class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def __repr__(self):
        return f"<Notification for {self.user_id}>"


# Auto-create notifications when a transaction happens

def create_notification(mapper, connection, target):
    """ Trigger notification when a user borrows or returns an item """
    message = f"You {target.action}ed an item (ID: {target.item_id})."
    notification = Notification(user_id=target.user_id, message=message)
    db.session.add(notification)
    db.session.commit()

listen(Transaction, 'after_insert', create_notification)
