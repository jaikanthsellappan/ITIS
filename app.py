from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
import io
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'rishekeshris@gmail.com'
app.config['MAIL_PASSWORD'] = 'xtbk zntk hiqa jgbq'
mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

    def is_admin(self):
        return self.role == 'admin'

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)  # BLOB to store the digital copy

def add_sample_books():
    with app.app_context():
        db.create_all()
    sample_books = [
        {'title': 'Book One', 'author': 'Author One', 'file_path': 'C:/Users/Welcome/Downloads/ITIS_assignment_2.pdf'},
        {'title': 'Book Two', 'author': 'Author Two', 'file_path': 'C:/Users/Welcome/Downloads/ITIS_assignment_2.pdf'},
        {'title': 'Book Three', 'author': 'Author Three', 'file_path': 'C:/Users/Welcome/Downloads/ITIS_assignment_2.pdf'}
    ]
    
    for book in sample_books:
        with open(book['file_path'], 'rb') as file:
            content = file.read()
        new_book = Book(title=book['title'], author=book['author'], content=content)
        db.session.add(new_book)
    
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_password_valid(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character."
    if re.search(r'\s', password):
        return False, "Password must not contain spaces."
    return True, ""

def is_email_valid(email):
    email_regex = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    if not email_regex.match(email):
        return False, "Invalid email format."
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return False, "Email is already in use."
    return True, ""

@app.route('/')
@login_required
def home():
    books = Book.query.all()
    return render_template('home.html', books=books)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        search_query = request.form['search']
        books = Book.query.filter((Book.title.contains(search_query)) | (Book.author.contains(search_query))).all()
        return render_template('home.html', books=books)
    return redirect(url_for('home'))

@app.route('/download/<int:book_id>')
@login_required
def download(book_id):
    book = Book.query.get_or_404(book_id)
    return send_file(io.BytesIO(book.content), as_attachment=True, download_name=f"{book.title}.pdf")

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        role = request.form['role']  # Get the role from the form

        valid_email, email_message = is_email_valid(email)
        if not valid_email:
            flash(email_message, 'danger')
            return redirect(url_for('signup'))

        valid_password, password_message = is_password_valid(password)
        if not valid_password:
            flash(password_message, 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # add_sample_books()
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    if not current_user.is_admin():
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('home'))
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')

@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='email-reset')
            msg = Message('Password Reset Request',
                          sender='your_email@gmail.com',
                          recipients=[email])
            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Your password reset link is {link}.'
            mail.send(msg)
            flash('A password reset email has been sent.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'danger')
    return render_template('request_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-reset', max_age=3600)
    except SignatureExpired:
        flash('The token is expired.', 'danger')
        return redirect(url_for('request_reset'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        valid_password, password_message = is_password_valid(password)
        if not valid_password:
            flash(password_message, 'danger')
            return redirect(url_for('reset_password', token=token))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    app.run(debug=True)
