from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from db import db
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Date, Float

Base = declarative_base()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)

    def check_password(self, password):
        # Implement password hashing and validation logic here
        return self.password == password

class EximExport(db.Model):
    __tablename__ = 'EximExport'
    SB_NO = db.Column(db.String, primary_key=True)
    SB_DATE = db.Column(db.Date)
    HS_CODE = db.Column(db.String)
    PRODUCT = db.Column(db.String)
    EXPORTER = db.Column(db.String)
    CONSIGNEE = db.Column(db.String)
    QTY = db.Column(db.Float)
    UNIT = db.Column(db.String)
    RATE_IN_FC = db.Column(db.Float)
    CURRENCY = db.Column(db.String)
    COUNTRY = db.Column(db.String)
    LOAD_PORT = db.Column(db.String)
    DESTI_PORT = db.Column(db.String)

class EximImport(db.Model):
    __tablename__ = 'EximImport'
    BE_NO = db.Column(db.String, primary_key=True)
    BE_DATE = db.Column(db.Date)
    HS_CODE = db.Column(db.String)
    PRODUCT = db.Column(db.String)
    IMPORTER = db.Column(db.String)
    SUPPLIER = db.Column(db.String)
    QTY = db.Column(db.Float)   
    UNIT = db.Column(db.String)
    RATE_IN_FC = db.Column(db.Float)
    CURRENCY = db.Column(db.String)
    COUNTRY = db.Column(db.String)
    LOAD_PORT = db.Column(db.String)
    DESTI_PORT = db.Column(db.String)

class SavedQuery(db.Model):
    __tablename__ = 'saved_queries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    conditions = db.Column(db.Text, nullable=False)
    search_type = db.Column(db.String(50), nullable=False)
    date_start = db.Column(db.Date, nullable=True)
    date_end = db.Column(db.Date, nullable=True)
    user = db.relationship('User', backref=db.backref('saved_queries', lazy=True))
