from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from flask_bootstrap import Bootstrap5
from sqlalchemy import Integer, String, Boolean, ForeignKey
from flask_login import LoginManager,login_user,UserMixin,login_required
from werkzeug.security import check_password_hash,generate_password_hash
# from flask_wtf.csrf import CSRFProtect
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ftyfguhijijokopkopkpok'
app.config["SQLALCHEMY_DATABASE_URI"] = r"sqlite:///D:\project\python\89-TO-do-list\instance\project.db"
@app.before_request
def csrf_protection():
    if request.method=='POST':
        token=session.pop('_csrf_token', None)
        if not token or token!= request.form.get('_csrf_token'):
            flash('CSRF token missing or incorrect','error')
            return redirect(url_for('login'))
def generate_csrf():
    if '_csrf_token' not in session:
        session['_csrf_token']=secrets.token_hex(16)
    return session['_csrf_token']
app.jinja_env.globals['csrf_token'] = generate_csrf


# csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap5(app=app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return UserBase.query.get(int(user_id))

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

class Post(db.Model):
    __tablename__ = "list_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    postText: Mapped[str] = mapped_column(String(250), nullable=False, unique=False)
    done: Mapped[bool] = mapped_column(Boolean, default=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('user_base.id'))
    author = relationship('UserBase', back_populates='post')

class UserBase(UserMixin, db.Model):
    __tablename__ = 'user_base'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(200))
    post = relationship('Post', back_populates='author')

with app.app_context():
    db.create_all()

to_do_list = []

@app.route('/', methods=['POST', 'GET'])
@login_required
def home():
    if request.method == 'POST':
        text = request.form.get('item')
        if text:
            newPost = Post(postText=text)
            db.session.add(newPost)
            db.session.commit()
    
    result = db.session.execute(db.select(Post))
    all_posts = result.scalars().all()
    to_do_list.clear()
    for post in all_posts:
        to_do_list.append({'id': post.id, 'text': post.postText, 'done': post.done})

    enumerated_list = list(enumerate(to_do_list, start=1))
    return render_template('home.html', enumerated_list=enumerated_list)

@app.route('/del/<int:index>', methods=['POST', 'GET'])
def del_to_do(index):
    try:
        post_to_delete = db.get_or_404(Post, index)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Error deleting post with id {index}: {e}")
        return redirect(url_for('home'))

@app.route('/toggle_done/<int:index>', methods=['POST'])
def toggle_done(index):
    post = db.get_or_404(Post, index)
    post.done = not post.done
    db.session.commit()
    # return jsonify({'success': True})


@app.route('/signin', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = UserBase.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')


@app.route('/signup', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        if username and password and email:
            hashed_password=generate_password_hash(password,method='pbkdf2:sha256',salt_length=8)
            existing_user = db.session.execute(db.select(UserBase).where(UserBase.email == email)).scalar_one_or_none()
            if existing_user is None:
                newUser = UserBase(
                    name=username,
                    password=hashed_password,
                    email=email
                )
                db.session.add(newUser)
                db.session.commit()
                login_user(newUser)
                return redirect(url_for('home'))
            else:
                flash('Email already registered', 'error')
        else:
            flash('Please fill out all fields', 'error')
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
