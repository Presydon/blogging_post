import os
from dotenv import load_dotenv
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)
gravatar = Gravatar(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///informations.db")
db = SQLAlchemy()
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return RegisterUsers.query.get(int(user_id))

# @app.template_filter('gravatar')
# def gravatar(email):
#     email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
#     gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}"
#     return gravatar_url

# TODO: Create a User table for all your registered users. 
class RegisterUsers(UserMixin, db.Model):
    __tablename__ = 'registered_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comment = relationship('Comments', back_populates='comment_author')


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('registered_users.id'))
    author = relationship('RegisterUsers', back_populates='posts')
    comment_post = relationship('Comments', back_populates='parent_post')


class Comments(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    comment_author = relationship('RegisterUsers', back_populates='comment')
    author_id = db.Column(db.Integer, db.ForeignKey('registered_users.id'))
    parent_post = relationship('BlogPost', back_populates='comment_post')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    

with app.app_context():
    db.create_all()


# TODO: Create admin_only decorator.
def admin_only(func):
    @wraps(func)
    @login_required
    def decorator_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return decorator_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        salt_and_hashing = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=10,
        )
        try:
            user = RegisterUsers(
                name=form.name.data,
                email=form.email.data,
                password=salt_and_hashing,
            )
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        except IntegrityError as e:
            db.session.rollback()
            if 'UNIQUE constraint failed' in str(e):
                flash('User Already Exists.')
                return redirect(url_for('register'))
            else:
                flash('An Error Occured During Registration. Please Try Again Later')
                return redirect(url_for('register'))
    return render_template("register.html", form=form, current_user=current_user)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.execute(db.select(RegisterUsers).where(RegisterUsers.email == email)).scalar()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else: 
            flash('Invalid Username or Password!!', 'danger')
    return render_template("login.html", form=form, current_user=current_user)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments (
                text = comment_form.body.data,
                comment_author = current_user,
                parent_post = requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('Login required, Please Log In.')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=False)
