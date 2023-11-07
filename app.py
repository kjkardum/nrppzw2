from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

xss_enabled = False
broken_access_control_enabled = False

@login_manager.user_loader
def loaduser(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, default='User')
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    secret_note = db.Column(db.String(1000), default='This is your secret note, write anything here!')
    status = db.Column(db.String(100), default='Hiiii')

with app.app_context():
    db.create_all()
    if User.query.filter_by(admin=True).first() is None:
        admin = User(
            email='admin@app.com',
            username='Admin',
            password_hash=bcrypt.generate_password_hash('Passw0rd_').decode('utf-8'),
            admin=True)
        another_user = User(email='second@app.com',
                            username='Second',
                            password_hash=bcrypt.generate_password_hash('youdontknowmypassword').decode('utf-8'),
                            secret_note='Oh no, you found my secret note!',
                            status='<script>alert("Second user says hi!")</script>')
        db.session.add(admin)
        db.session.add(another_user)
        db.session.commit()

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template(
        'index.html',
        xss_enabled=xss_enabled,
        broken_access_control_enabled=broken_access_control_enabled,
        users = list(map(lambda i:{"username": i.username, "status": i.status}, User.query.all())))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not request.form.get('email') or not request.form.get('password'):
            flash('Please fill in all fields', 'error')
            return redirect(url_for('login'))
        else:
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user and bcrypt.check_password_hash(user.password_hash, request.form.get('password')):
                login_user(user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            elif not user:
                flash('User not found.', 'error')
                return redirect(url_for('login'))
            else:
                flash('Invalid credentials.', 'error')
                return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/xss', methods=['GET'])
@login_required
def toggle_xss():
    if not current_user.admin:
        return 'NOT_ADMIN', 403
    global xss_enabled
    xss_enabled = not xss_enabled
    flash(f'XSS {"enabled" if xss_enabled else "disabled"}', 'success')
    return redirect(url_for('index'))

@app.route('/broken_access_control', methods=['GET'])
@login_required
def toggle_broken_access_control():
    if not current_user.admin:
        return 'NOT_ADMIN', 403
    global broken_access_control_enabled
    broken_access_control_enabled = not broken_access_control_enabled
    flash(f'Broken access control {"enabled" if broken_access_control_enabled else "disabled"}', 'success')
    return redirect(url_for('index'))

@app.route('/profile/<user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return 'User not found', 404
    if not broken_access_control_enabled and current_user.id != user.id:
        flash('You cannot view other users\' profiles.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        if not request.form.get('status') or not request.form.get('secret_note'):
            flash('Please fill in all fields', 'error')
            return redirect(url_for('profile', user_id=user_id))
        else:
            user.status = request.form.get('status')
            user.secret_note = request.form.get('secret_note')
            db.session.commit()
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile', user_id=user_id))
    return render_template('profile.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
