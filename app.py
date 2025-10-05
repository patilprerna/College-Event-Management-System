import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
# Yahan badlav kiya gaya hai: DateField ko seedhe wtforms se import kiya gaya hai
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# ===================================================
# App Configuration
# ===================================================

app = Flask(__name__)
# Aapko yaha apna secret key daalna hoga
app.config['SECRET_KEY'] = 'your_super_secret_key_change_it' 
# Database URI: mysql+pymysql://username:password@host/database_name
# Apna MySQL username, password, aur database name yaha daalein
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mysql1234@localhost/college_events'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Agar user login nahi hai to 'login' page par redirect karega
login_manager.login_message_category = 'info'

# ===================================================
# Database Models
# ===================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    registrations = db.relationship('Registration', backref='attendee', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    location = db.Column(db.String(100), nullable=False)
    registrations = db.relationship('Registration', backref='event_registered', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"Event('{self.name}', '{self.date}')"

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    def __repr__(self):
        return f"Registration('User {self.user_id}', 'Event {self.event_id}')"

# ===================================================
# Forms
# ===================================================

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class EventForm(FlaskForm):
    name = StringField('Event Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateField('Event Date', format='%Y-%m-%d', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    submit = SubmitField('Submit Event')

# ===================================================
# Routes
# ===================================================

@app.route("/")
@app.route("/home")
def index():
    events = Event.query.order_by(Event.date.asc()).all()
    return render_template('index.html', events=events, title='Upcoming Events')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login Successful!', 'success')
            if user.is_admin:
                return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
            else:
                return redirect(next_page) if next_page else redirect(url_for('student_dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. You must be an admin to view this page.', 'danger')
        return redirect(url_for('index'))
    
    events = Event.query.order_by(Event.date.desc()).all()
    users = User.query.all()
    registrations = Registration.query.all()
    
    event_registration_counts = {}
    for event in events:
        count = Registration.query.filter_by(event_id=event.id).count()
        event_registration_counts[event.id] = count

    return render_template('admin_dashboard.html', 
                            title='Admin Dashboard', 
                            events=events, 
                            users=users, 
                            registrations=registrations,
                            event_counts=event_registration_counts)

@app.route("/dashboard")
@login_required
def student_dashboard():
    registered_events_ids = [reg.event_id for reg in current_user.registrations]
    registered_events = Event.query.filter(Event.id.in_(registered_events_ids)).all()
    return render_template('student_dashboard.html', title='My Dashboard', events=registered_events)

@app.route("/event/new", methods=['GET', 'POST'])
@login_required
def new_event():
    if not current_user.is_admin:
        flash('You do not have permission to create an event.', 'danger')
        return redirect(url_for('index'))
    form = EventForm()
    if form.validate_on_submit():
        event = Event(name=form.name.data, description=form.description.data, date=form.date.data, location=form.location.data)
        db.session.add(event)
        db.session.commit()
        flash('The event has been created!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('event_form.html', title='New Event', form=form, legend='Create New Event')

@app.route("/event/<int:event_id>/update", methods=['GET', 'POST'])
@login_required
def update_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not current_user.is_admin:
        flash('You do not have permission to update this event.', 'danger')
        return redirect(url_for('index'))
    form = EventForm()
    if form.validate_on_submit():
        event.name = form.name.data
        event.description = form.description.data
        event.date = form.date.data
        event.location = form.location.data
        db.session.commit()
        flash('The event has been updated!', 'success')
        return redirect(url_for('admin_dashboard'))
    elif request.method == 'GET':
        form.name.data = event.name
        form.description.data = event.description
        form.date.data = event.date
        form.location.data = event.location
    return render_template('event_form.html', title='Update Event', form=form, legend=f'Update {event.name}')

@app.route("/event/<int:event_id>/delete", methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not current_user.is_admin:
        flash('You do not have permission to delete this event.', 'danger')
        return redirect(url_for('index'))
    db.session.delete(event)
    db.session.commit()
    flash('The event has been deleted!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/event/<int:event_id>/register", methods=['POST'])
@login_required
def register_for_event(event_id):
    event = Event.query.get_or_404(event_id)
    existing_registration = Registration.query.filter_by(user_id=current_user.id, event_id=event.id).first()
    
    if existing_registration:
        flash('You are already registered for this event.', 'info')
    else:
        registration = Registration(user_id=current_user.id, event_id=event.id)
        db.session.add(registration)
        db.session.commit()
        flash(f'You have successfully registered for {event.name}!', 'success')
    return redirect(url_for('index'))

@app.route("/event/<int:event_id>/unregister", methods=['POST'])
@login_required
def unregister_from_event(event_id):
    registration = Registration.query.filter_by(user_id=current_user.id, event_id=event_id).first()
    if registration:
        db.session.delete(registration)
        db.session.commit()
        flash('You have successfully unregistered from the event.', 'success')
    else:
        flash('You were not registered for this event.', 'info')
    return redirect(url_for('student_dashboard'))


# ===================================================
# Main
# ===================================================
if __name__ == '__main__':
    # Ek baar database create karne ke liye
    with app.app_context():
        db.create_all()
    app.run(debug=True)

