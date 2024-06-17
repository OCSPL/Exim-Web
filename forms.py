from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, FieldList, FormField, DateField
from wtforms.validators import DataRequired, Email, Optional
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

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
    delete = SubmitField('Delete')

class DynamicSearchForm(FlaskForm):
    saved_query = SelectField('Saved Query', choices=[('', 'Select a saved query')])  # Add default option
    search_type = SelectField('Search Type', choices=[('import', 'Import'), ('export', 'Export')])
    date_start = DateField('Start Date', format='%Y-%m-%d', validators=[Optional()])
    date_end = DateField('End Date', format='%Y-%m-%d', validators=[Optional()])
    conditions = FieldList(FormField(ConditionForm), min_entries=1)
    save_query = StringField('Save Query As')
    add_condition = SubmitField('Add Condition')
    submit = SubmitField('Search')
    save = SubmitField('Save')
    load = SubmitField('Load')  # Add a button to load the selected saved query










