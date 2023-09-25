from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, InputRequired, Email, Length, EqualTo
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()], render_kw={'placeholder': 'Enter username'})
    email = StringField('Email', validators=[InputRequired(), Email(granular_message=True)], render_kw={'placeholder': 'example@email.com'})
    password = PasswordField('Password', validators=[InputRequired(), EqualTo('confirm', message='Passwords must match'), 
                                          Length(min=8, message="Password must be at least 8 characters long")], render_kw={'placeholder': 'More than 8 characters'})
    confirm = PasswordField('Repeat Password', validators=[InputRequired()], render_kw={'placeholder': 'More than 8 characters'})
    submit = SubmitField('Submit')


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(granular_message=True)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    body = CKEditorField("Comment")
    submit = SubmitField('Submit Comment')