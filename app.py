from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, Response
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, FieldList, FormField, DateField, HiddenField
from wtforms.validators import DataRequired, Email, Optional
import os
from dotenv import load_dotenv
from flask_migrate import Migrate
import plotly.graph_objs as go
import plotly.io as pio
import json
import pandas as pd
from sqlalchemy import text
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from forms import ChangePasswordForm

# Load environment variables
load_dotenv()

# Debugging: Print environment variables
print("Environment Variables:")
for key in ["SECRET_KEY", "DATABASE_URI"]:
    print(f"{key}: {os.getenv(key)}")

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'mssql+pyodbc://@LT30HOIT/Ocspl_exim?trusted_connection=yes&driver=ODBC+Driver+17+for+SQL+Server')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Use True if your site is served over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Options: 'Strict', 'Lax', 'None'
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token timeout

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize SQLAlchemy, Migrate, and LoginManager
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
# User model with password_hash
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)
    approved = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='user')
    active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.active

    @is_active.setter
    def is_active(self, value):
        self.active = value
    
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

class GlobalQuery(db.Model):
    __tablename__ = 'global_queries'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    conditions = db.Column(db.Text, nullable=False)
    search_type = db.Column(db.String(50), nullable=False)
    date_start = db.Column(db.Date, nullable=True)
    date_end = db.Column(db.Date, nullable=True)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional(), Email()])
    submit = SubmitField('Register')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ConditionForm(FlaskForm):
    column = SelectField('Column', choices=[])  # Choices will be populated dynamically
    condition = SelectField('Condition', choices=[
        ('contains', 'Contains'), 
        ('not_contains', 'Does Not Contain'),
        ('equals', 'Equals'),
        ('not_equals', 'Not Equals'),
        ('greater_than', 'Greater Than'),
        ('less_than', 'Less Than'),
        ('greater_than_equal', 'Greater Than or Equal'),
        ('less_than_equal', 'Less Than or Equal')
    ])
    value = StringField('Value', validators=[DataRequired()])

class DynamicSearchForm(FlaskForm):
    search_type = SelectField('Search Type', choices=[('import', 'Import'), ('export', 'Export')])
    date_start = DateField('Start Date', format='%Y-%m-%d', validators=[Optional()])
    date_end = DateField('End Date', format='%Y-%m-%d', validators=[Optional()])
    conditions = FieldList(FormField(ConditionForm), min_entries=1)
    save_query = StringField('Save Query As', validators=[Optional()])
    add_condition = SubmitField('Add Condition')
    submit = SubmitField('Search')
    save = SubmitField('Save')
    global_query_name = StringField('Global Query Name', validators=[Optional()])
    save_global = SubmitField('Save as Global Query')
    loaded_query_id = HiddenField('Loaded Query ID')  # Add this line

class GlobalQueryForm(FlaskForm):
    name = StringField('Global Query Name')
    submit = SubmitField('Save as Global Query')

class UploadForm(FlaskForm):
    upload_type = SelectField('Upload Type', choices=[('import', 'Import'), ('export', 'Export')], validators=[DataRequired()])
    file = FileField('Select CSV File', validators=[FileRequired(), FileAllowed(['csv'], 'CSV files only!')])
    submit = SubmitField('Upload')

class SavedQueryForm(FlaskForm):
    query_id = HiddenField('query_id', validators=[DataRequired()])
    submit = SubmitField('Delete')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def get_column_choices(search_type):
    if search_type == 'export':
        return [(column.name, column.name) for column in EximExport.__table__.columns]
    else:
        return [(column.name, column.name) for column in EximImport.__table__.columns]

def check_auth(username, password):
    """This function is called to check if a username/password combination is valid."""
    return username == 'admin' and password == 'admin_password'

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            if existing_user.username == form.username.data:
                flash('Username already exists.', 'danger')
            if existing_user.email == form.email.data:
                flash('Email already exists.', 'danger')
        else:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)  # Hash the password
            try:
                db.session.add(user)
                db.session.commit()
                flash('New user added successfully.', 'success')
                return redirect(url_for('register'))  # Redirect to the register page to display the success message
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding user: {str(e)}", 'danger')
    return render_template('register.html', form=form)

@app.route('/create_admin', methods=['GET', 'POST'])
@requires_auth
def create_admin():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            if existing_user.username == form.username.data:
                flash('Username already exists.', 'danger')
            if existing_user.email == form.email.data:
                flash('Email already exists.', 'danger')
        else:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)  # Hash the password
            user.approved = True  # Automatically approve the admin user
            user.role = 'admin'  # Set the role to admin
            try:
                db.session.add(user)
                db.session.commit()
                flash('Admin user created successfully.', 'success')
                return redirect(url_for('create_admin'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding admin user: {str(e)}", 'danger')
    return render_template('register.html', form=form)

@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        return redirect(url_for('index_get'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/deactivate_user/<int:user_id>')
@login_required
def deactivate_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index_get'))
    user = User.query.get(user_id)
    if user:
        user.is_active = False
        db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/activate_user/<int:user_id>')
@login_required
def activate_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index_get'))
    user = User.query.get(user_id)
    if user:
        user.is_active = True
        db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index_get'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.get(current_user.id)
        if user and user.check_password(form.old_password.data):
            user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('index_get'))
        else:
            flash('Old password is incorrect.', 'danger')
    return render_template('change_password.html', form=form)

@app.route('/approve_users')
@login_required
def approve_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index_get'))
    
    users = User.query.filter_by(approved=False).all()
    return render_template('approve_users.html', users=users)

@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index_get'))
    
    user = User.query.get(user_id)
    if user:
        user.approved = True
        db.session.commit()
        flash(f'User {user.username} has been approved.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('approve_users'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.check_password(form.password.data):
                if user.approved:
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('index_get'))
                else:
                    flash('Your account is not approved yet.', 'warning')
            else:
                flash('Invalid username or password', 'error')
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/protected_route')
@login_required
def protected_route():
    return 'This is a protected route'

@app.route('/index')
@login_required
def index_get():
    form = DynamicSearchForm()
    form.date_end.data = date.today()  # Set default value for date_end to today's date
    saved_queries = SavedQuery.query.filter_by(user_id=current_user.id).all()
    global_queries = GlobalQuery.query.all()

    # Populate the form if query parameters are present
    search_type = request.args.get('search_type')
    date_start = request.args.get('date_start')
    date_end = request.args.get('date_end')
    conditions = request.args.get('conditions')

    if search_type:
        form.search_type.data = search_type
    if date_start:
        form.date_start.data = date.fromisoformat(date_start)
    if date_end:
        form.date_end.data = date.fromisoformat(date_end)
    if conditions:
        conditions_list = json.loads(conditions)
        form.conditions.entries = []
        for condition in conditions_list:
            condition_form = ConditionForm()
            condition_form.column.choices = get_column_choices(search_type)
            condition_form.column.data = condition['column']
            condition_form.condition.data = condition['condition']
            condition_form.value.data = condition['value']
            form.conditions.append_entry(condition_form)

    return render_template('index.html', form=form, results=None, saved_queries=saved_queries, global_queries=global_queries)

@app.route('/index', methods=['POST'])
@login_required
def index_post():
    form = DynamicSearchForm()
    saved_queries = SavedQuery.query.filter_by(user_id=current_user.id).all()
    global_queries = GlobalQuery.query.all()

    # Set choices for column select fields dynamically based on the search type
    for condition_form in form.conditions:
        condition_form.column.choices = get_column_choices(form.search_type.data)

    if form.add_condition.data:
        form.conditions.append_entry()
        for condition_form in form.conditions:
            condition_form.column.choices = get_column_choices(form.search_type.data)
        return render_template('index.html', form=form, results=None, saved_queries=saved_queries, global_queries=global_queries)

    if form.validate_on_submit():
        results = {'exports': [], 'imports': []}
        export_graph = None
        import_graph = None

        search_type = form.search_type.data
        conditions = form.conditions.data
        date_start = form.date_start.data
        date_end = form.date_end.data

        if search_type == 'export':
            query = db.session.query(EximExport)
        else:
            query = db.session.query(EximImport)

        for condition in conditions:
            column = condition['column']
            condition_type = condition['condition']
            value = condition['value']

            if condition_type == 'contains':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column).like(f'%{value}%'))
            elif condition_type == 'not_contains':
                query = query.filter(~getattr(EximExport if search_type == 'export' else EximImport, column).like(f'%{value}%'))
            elif condition_type == 'equals':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) == value)
            elif condition_type == 'not_equals':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) != value)
            elif condition_type == 'greater_than':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) > float(value))
            elif condition_type == 'less_than':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) < float(value))
            elif condition_type == 'greater_than_equal':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) >= float(value))
            elif condition_type == 'less_than_equal':
                query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) <= float(value))

        if date_start:
            query = query.filter(EximExport.SB_DATE >= date_start if search_type == 'export' else EximImport.BE_DATE >= date_start)
        if date_end:
            query = query.filter(EximExport.SB_DATE <= date_end if search_type == 'export' else EximImport.BE_DATE <= date_end)

        results_data = query.all()

        # Debugging: Print the number of results
        print(f"Number of results: {len(results_data)}")

        # Filter out None values
        results_data = [exp for exp in results_data if exp is not None]

        if search_type == 'export':
            if results_data:
                export_data = {
                    'SB_NO': [exp.SB_NO for exp in results_data],
                    'SB_DATE': [exp.SB_DATE for exp in results_data],
                    'HS_CODE': [exp.HS_CODE for exp in results_data],
                    'PRODUCT': [exp.PRODUCT for exp in results_data],
                    'EXPORTER': [exp.EXPORTER for exp in results_data],
                    'CONSIGNEE': [exp.CONSIGNEE for exp in results_data],
                    'QTY': [exp.QTY for exp in results_data],
                    'UNIT': [exp.UNIT for exp in results_data],
                    'RATE_IN_FC': [exp.RATE_IN_FC for exp in results_data],
                    'CURRENCY': [exp.CURRENCY for exp in results_data],
                    'COUNTRY': [exp.COUNTRY for exp in results_data],
                    'LOAD_PORT': [exp.LOAD_PORT for exp in results_data],
                    'DESTI_PORT': [exp.DESTI_PORT for exp in results_data]
                }
                export_graph = pio.to_html(go.Figure(data=[
                    go.Bar(x=export_data['SB_NO'], y=export_data['QTY'], name='Export Quantities')
                ]), full_html=False)

            results = {'exports': results_data, 'imports': []}

        else:
            if results_data:
                import_data = {
                    'BE_NO': [imp.BE_NO for imp in results_data],
                    'BE_DATE': [imp.BE_DATE for imp in results_data],
                    'HS_CODE': [imp.HS_CODE for imp in results_data],
                    'PRODUCT': [imp.PRODUCT for imp in results_data],
                    'IMPORTER': [imp.IMPORTER for imp in results_data],
                    'SUPPLIER': [imp.SUPPLIER for imp in results_data],
                    'QTY': [imp.QTY for imp in results_data],
                    'UNIT': [imp.UNIT for imp in results_data],
                    'RATE_IN_FC': [imp.RATE_IN_FC for imp in results_data],
                    'CURRENCY': [imp.CURRENCY for imp in results_data],
                    'COUNTRY': [imp.COUNTRY for imp in results_data],
                    'LOAD_PORT': [imp.LOAD_PORT for imp in results_data],
                    'DESTI_PORT': [imp.DESTI_PORT for imp in results_data]
                }
                import_graph = pio.to_html(go.Figure(data=[
                    go.Bar(x=import_data['BE_NO'], y=import_data['QTY'], name='Import Quantities')
                ]), full_html=False)

            results = {'exports': [], 'imports': results_data}

        results_data_json = json.dumps([exp.__dict__ for exp in results_data], default=str)

        loaded_query_id = form.loaded_query_id.data
        save_query_name = form.save_query.data.strip()
        global_query_name = form.global_query_name.data.strip()

        if form.save.data and save_query_name:
            conditions_to_save = [{'column': cond['column'], 'condition': cond['condition'], 'value': cond['value']} for cond in conditions]
            print("Saving local query with conditions:", conditions_to_save)  # Debugging

            if loaded_query_id:
                saved_query = SavedQuery.query.get(loaded_query_id)
                if saved_query and saved_query.user_id == current_user.id:
                    saved_query.name = save_query_name
                    saved_query.conditions = json.dumps(conditions_to_save)
                    saved_query.search_type = search_type
                    saved_query.date_start = date_start
                    saved_query.date_end = date_end
            else:
                saved_query = SavedQuery(
                    user_id=current_user.id,
                    name=save_query_name,
                    conditions=json.dumps(conditions_to_save),
                    search_type=search_type,
                    date_start=date_start,
                    date_end=date_end
                )
                db.session.add(saved_query)

            try:
                db.session.commit()
                flash('Query saved successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving query: {str(e)}", 'error')

        if form.save_global.data and global_query_name:
            conditions_to_save = [{'column': cond['column'], 'condition': cond['condition'], 'value': cond['value']} for cond in conditions]
            print("Saving global query with conditions:", conditions_to_save)  # Debugging

            if loaded_query_id:
                global_query = GlobalQuery.query.get(loaded_query_id)
                if global_query:
                    global_query.name = global_query_name
                    global_query.conditions = json.dumps(conditions_to_save)
                    global_query.search_type = search_type
                    global_query.date_start = date_start
                    global_query.date_end = date_end
            else:
                global_query = GlobalQuery(
                    name=global_query_name,
                    conditions=json.dumps(conditions_to_save),
                    search_type=search_type,
                    date_start=date_start,
                    date_end=date_end
                )
                db.session.add(global_query)

            try:
                db.session.commit()
                flash('Global query saved successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving global query: {str(e)}", 'danger')

        return render_template('index.html', form=form, results=results, export_graph=export_graph, import_graph=import_graph, results_data=results_data_json, saved_queries=saved_queries, global_queries=global_queries)

    return render_template('index.html', form=form, results=None, saved_queries=saved_queries, global_queries=global_queries)

@app.route('/load_saved_query/<int:query_id>', methods=['GET'])
@login_required
def load_saved_query(query_id):
    saved_query = SavedQuery.query.get(query_id)
    if not saved_query or saved_query.user_id != current_user.id:
        flash('Saved query not found or access denied.', 'error')
        return redirect(url_for('index_get'))

    query_data = {
        'search_type': saved_query.search_type,
        'date_start': saved_query.date_start.strftime('%Y-%m-%d') if saved_query.date_start else '',
        'date_end': saved_query.date_end.strftime('%Y-%m-%d') if saved_query.date_end else '',
        'conditions': json.loads(saved_query.conditions)
    }

    return jsonify(query_data)

@app.route('/save_global_query', methods=['POST'])
def save_global_query():
    form = DynamicSearchForm()
    if form.validate_on_submit():
        name = form.global_query_name.data
        existing_query = GlobalQuery.query.filter_by(name=name).first()
        if existing_query:
            flash('Query with this name already exists.', 'danger')
        else:
            conditions_to_save = [{'column': cond['column'], 'condition': cond['condition'], 'value': cond['value']} for cond in form.conditions.data]
            global_query = GlobalQuery(
                name=name,
                conditions=json.dumps(conditions_to_save),
                search_type=form.search_type.data,
                date_start=form.date_start.data,
                date_end=form.date_end.data
            )
            try:
                db.session.add(global_query)
                db.session.commit()
                flash('Global query saved successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving global query: {str(e)}", 'danger')
    return redirect(url_for('index_get'))

@app.route('/load_global_query/<int:query_id>', methods=['GET'])
def load_global_query(query_id):
    global_query = GlobalQuery.query.get(query_id)
    if not global_query:
        flash('Global query not found.', 'danger')
        return redirect(url_for('index_get'))

    query_data = {
        'search_type': global_query.search_type,
        'date_start': global_query.date_start.strftime('%Y-%m-%d') if global_query.date_start else '',
        'date_end': global_query.date_end.strftime('%Y-%m-%d') if global_query.date_end else '',
        'conditions': json.loads(global_query.conditions)
    }

    return jsonify(query_data)

@app.route('/global_queries')
def global_queries():
    form = DynamicSearchForm()  # Pass the form to the template
    queries = GlobalQuery.query.all()
    for query in queries:
        query.conditions = json.loads(query.conditions)
    return render_template('global_queries.html', queries=queries, form=form)

@app.route('/clear_filters')
@login_required
def clear_filters():
    return redirect(url_for('index_get'))

@app.route('/saved_queries')
@login_required
def saved_queries():
    form = DynamicSearchForm()  # Pass the form to the template
    queries = SavedQuery.query.filter_by(user_id=current_user.id).all()
    for query in queries:
        query.conditions = json.loads(query.conditions)
    return render_template('saved_queries.html', queries=queries, form=form)

@app.route('/delete_saved_query/<int:query_id>', methods=['POST'])
@login_required
@csrf.exempt  # This is optional and can be used if CSRF validation is causing issues
def delete_saved_query(query_id):
    saved_query = SavedQuery.query.get(query_id)
    if not saved_query or saved_query.user_id != current_user.id:
        flash('Saved query not found or access denied.', 'error')
        return redirect(url_for('saved_queries'))

    try:
        db.session.delete(saved_query)
        db.session.commit()
        flash('Saved query deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting saved query: {str(e)}", 'danger')
    return redirect(url_for('saved_queries'))

@app.route('/delete_global_query/<int:query_id>', methods=['POST'])
@login_required
def delete_global_query(query_id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete this global query.', 'danger')
        return redirect(url_for('global_queries'))

    global_query = GlobalQuery.query.get(query_id)
    if not global_query:
        flash('Global query not found.', 'error')
        return redirect(url_for('global_queries'))

    try:
        db.session.delete(global_query)
        db.session.commit()
        flash('Global query deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting global query: {str(e)}", 'danger')
    return redirect(url_for('global_queries'))

@app.route('/get_columns/<search_type>', methods=['GET'])
@login_required
def get_columns(search_type):
    if search_type == 'export':
        columns = [column.name for column in EximExport.__table__.columns]
    else:
        columns = [column.name for column in EximImport.__table__.columns]
    return jsonify(columns)

# Imports and setup are assumed to be above this section.

@app.route('/run_query/<int:query_id>', methods=['GET'])
@login_required
def run_query(query_id):
    global_query = GlobalQuery.query.get(query_id)
    if not global_query:
        flash('Global query not found.', 'danger')
        return redirect(url_for('global_queries'))

    # Convert query conditions to the appropriate format
    query_data = {
        'search_type': global_query.search_type,
        'date_start': global_query.date_start.strftime('%Y-%m-%d') if global_query.date_start else '',
        'date_end': global_query.date_end.strftime('%Y-%m-%d') if global_query.date_end else '',
        'conditions': json.loads(global_query.conditions)
    }

    search_type = query_data['search_type']
    date_start = query_data['date_start']
    date_end = query_data['date_end']
    conditions = query_data['conditions']

    if search_type == 'export':
        query = db.session.query(EximExport)
    else:
        query = db.session.query(EximImport)

    for condition in conditions:
        column = condition['column']
        condition_type = condition['condition']
        value = condition['value']

        if condition_type == 'contains':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column).like(f'%{value}%'))
        elif condition_type == 'not_contains':
            query = query.filter(~getattr(EximExport if search_type == 'export' else EximImport, column).like(f'%{value}%'))
        elif condition_type == 'equals':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) == value)
        elif condition_type == 'not_equals':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) != value)
        elif condition_type == 'greater_than':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) > float(value))
        elif condition_type == 'less_than':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) < float(value))
        elif condition_type == 'greater_than_equal':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) >= float(value))
        elif condition_type == 'less_than_equal':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) <= float(value))

    if date_start:
        query = query.filter(EximExport.SB_DATE >= date_start if search_type == 'export' else EximImport.BE_DATE >= date_start)
    if date_end:
        query = query.filter(EximExport.SB_DATE <= date_end if search_type == 'export' else EximImport.BE_DATE <= date_end)

    results_data = query.all()
    results_data = [exp for exp in results_data if exp is not None]

    # Render the results
    results_html = render_template('results.html', results=results_data, search_type=search_type)
    return results_html

@app.route('/run_saved_query/<int:query_id>', methods=['GET'])
@login_required
def run_saved_query(query_id):
    saved_query = SavedQuery.query.get(query_id)
    if not saved_query or saved_query.user_id != current_user.id:
        flash('Saved query not found or access denied.', 'error')
        return redirect(url_for('saved_queries'))

    # Convert query conditions to the appropriate format
    query_data = {
        'search_type': saved_query.search_type,
        'date_start': saved_query.date_start.strftime('%Y-%m-%d') if saved_query.date_start else '',
        'date_end': datetime.today().strftime('%Y-%m-%d'),  # Always use the current date for date_end
        'conditions': json.loads(saved_query.conditions)
    }

    search_type = query_data['search_type']
    date_start = query_data['date_start']
    date_end = query_data['date_end']
    conditions = query_data['conditions']

    if search_type == 'export':
        query = db.session.query(EximExport)
    else:
        query = db.session.query(EximImport)

    for condition in conditions:
        column = condition['column']
        condition_type = condition['condition']
        value = condition['value']

        if condition_type == 'contains':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column).like(f'%{value}%'))
        elif condition_type == 'not_contains':
            query = query.filter(~getattr(EximExport if search_type == 'export' else EximImport, column).like(f'%{value}%'))
        elif condition_type == 'equals':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) == value)
        elif condition_type == 'not_equals':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) != value)
        elif condition_type == 'greater_than':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) > float(value))
        elif condition_type == 'less_than':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) < float(value))
        elif condition_type == 'greater_than_equal':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) >= float(value))
        elif condition_type == 'less_than_equal':
            query = query.filter(getattr(EximExport if search_type == 'export' else EximImport, column) <= float(value))

    if date_start:
        query = query.filter(EximExport.SB_DATE >= date_start if search_type == 'export' else EximImport.BE_DATE >= date_start)
    if date_end:
        query = query.filter(EximExport.SB_DATE <= date_end if search_type == 'export' else EximImport.BE_DATE <= date_end)

    results_data = query.all()
    results_data = [exp for exp in results_data if exp is not None]

    # Render the results
    results_html = render_template('results.html', results=results_data, search_type=search_type)
    return results_html

@app.route('/autocomplete', methods=['GET'])
@login_required
def autocomplete():
    term = request.args.get('term')
    search_type = request.args.get('search_type')
    
    if search_type == 'export':
        model = EximExport
    else:
        model = EximImport

    suggestions = []
    for column in model.__table__.columns:
        column_attr = getattr(model, column.name)
        query_results = db.session.query(column_attr).filter(column_attr.like(f'%{term}%')).distinct().all()
        for result in query_results:
            suggestions.append(str(result[0]))

    return jsonify(list(set(suggestions)))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index_get'))
    
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        upload_type = form.upload_type.data
        try:
            df = pd.read_csv(file)
            # Perform data validation and cleaning here if necessary
            # Save the data to the database based on the selected upload type
            if upload_type == 'export':
                for index, row in df.iterrows():
                    exim_export = EximExport(
                        SB_NO=row['SB_NO'],
                        SB_DATE=pd.to_datetime(row['SB_DATE']),
                        HS_CODE=row['HS_CODE'],
                        PRODUCT=row['PRODUCT'],
                        EXPORTER=row['EXPORTER'],
                        CONSIGNEE=row['CONSIGNEE'],
                        QTY=row['QTY'],
                        UNIT=row['UNIT'],
                        RATE_IN_FC=row['RATE_IN_FC'],
                        CURRENCY=row['CURRENCY'],
                        COUNTRY=row['COUNTRY'],
                        LOAD_PORT=row['LOAD_PORT'],
                        DESTI_PORT=row['DESTI_PORT']
                    )
                    db.session.add(exim_export)
            elif upload_type == 'import':
                for index, row in df.iterrows():
                    exim_import = EximImport(
                        BE_NO=row['BE_NO'],
                        BE_DATE=pd.to_datetime(row['BE_DATE']),
                        HS_CODE=row['HS_CODE'],
                        PRODUCT=row['PRODUCT'],
                        IMPORTER=row['IMPORTER'],
                        SUPPLIER=row['SUPPLIER'],
                        QTY=row['QTY'],
                        UNIT=row['UNIT'],
                        RATE_IN_FC=row['RATE_IN_FC'],
                        CURRENCY=row['CURRENCY'],
                        COUNTRY=row['COUNTRY'],
                        LOAD_PORT=row['LOAD_PORT'],
                        DESTI_PORT=row['DESTI_PORT']
                    )
                    db.session.add(exim_import)
            db.session.commit()
            flash('File uploaded and data saved successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading file: {str(e)}', 'danger')
        return redirect(url_for('upload'))
    return render_template('upload.html', form=form)

@app.route('/download_results/<string:search_type>', methods=['POST'])
@login_required
@csrf.exempt  # Exempt the route from CSRF protection (use only if necessary)
def download_results(search_type):
    results_data = request.form.get('results_data')
    if results_data:
        results = json.loads(results_data)
        if search_type == 'export':
            df = pd.DataFrame([{
                'SB_NO': exp['SB_NO'],
                'SB_DATE': exp['SB_DATE'],
                'HS_CODE': exp['HS_CODE'],
                'PRODUCT': exp['PRODUCT'],
                'EXPORTER': exp['EXPORTER'],
                'CONSIGNEE': exp['CONSIGNEE'],
                'QTY': exp['QTY'],
                'UNIT': exp['UNIT'],
                'RATE_IN_FC': exp['RATE_IN_FC'],
                'CURRENCY': exp['CURRENCY'],
                'COUNTRY': exp['COUNTRY'],
                'LOAD_PORT': exp['LOAD_PORT'],
                'DESTI_PORT': exp['DESTI_PORT']
            } for exp in results])
        else:
            df = pd.DataFrame([{
                'BE_NO': imp['BE_NO'],
                'BE_DATE': imp['BE_DATE'],
                'HS_CODE': imp['HS_CODE'],
                'PRODUCT': imp['PRODUCT'],
                'IMPORTER': imp['IMPORTER'],
                'SUPPLIER': imp['SUPPLIER'],
                'QTY': imp['QTY'],
                'UNIT': imp['UNIT'],
                'RATE_IN_FC': imp['RATE_IN_FC'],
                'CURRENCY': imp['CURRENCY'],
                'COUNTRY': imp['COUNTRY'],
                'LOAD_PORT': imp['LOAD_PORT'],
                'DESTI_PORT': imp['DESTI_PORT']
            } for imp in results])

        response = make_response(df.to_csv(index=False))
        response.headers['Content-Disposition'] = f'attachment; filename={search_type}_results.csv'
        response.headers['Content-Type'] = 'text/csv'
        return response
    flash('No results data to download.', 'error')
    return redirect(url_for('index_get'))

@app.route('/test_db_connection')
def test_db_connection():
    try:
        result = db.session.execute(text('SELECT 1'))
        return jsonify({'message': 'Database connection successful', 'success': True})
    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}', 'success': False})

if __name__ == '__main__':
    app.run(debug=True, port=5001)
