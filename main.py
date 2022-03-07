from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from wtforms import StringField, SubmitField,SelectField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
from functools import wraps
import os
print("hi")



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def user_loader(user_id):

    return User.query.get(user_id)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])  
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])  
   
    submit = SubmitField('Log in')
##CONFIGURE TABLES
class User(UserMixin,db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    children = db.relationship("BlogPost")
  
class BlogPost(db.Model):
    __tablename__ = "Blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
# db.create_all()


  
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id!=1:
            return Abort(403)
        return f(*args, **kwargs)
    return decorated_function
    
# db.create_all()
print(User.query.all())

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    print(current_user.is_authenticated)
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)


@app.route('/register',methods=['POST','GET'])
def register():
    form=RegisterForm()
    if request.method == "POST":
      form=RegisterForm()
      data=form.email.data
      user = User.query.filter_by(email=data).first()
      all_user=User.query.all()
      has_password=generate_password_hash(form.password.data)
      if user in all_user:
        form=LoginForm()
        flash('Entered email already exit, please login ')
        return render_template("login.html",form=form)
      new_user=User(email=form.email.data,
                    password=has_password,
                    name=form.name.data)
      login_user(new_user)
      db.session.add(new_user)
      db.session.commit()
      print("adeded")
      posts = BlogPost.query.all()
      return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)
      
    return render_template("register.html",form=form,logged_in=current_user.is_authenticated)


@app.route('/login',methods=['POST','GET'])
def login():
    form=LoginForm()
    if request.method == "POST":
      # if form.validate_on_submit():
          form=LoginForm()
          data=form.email.data 
          user = User.query.filter_by(email=data).first()
          all_user=User.query.all()
          print(all_user)           
          if user in all_user:           
            if check_password_hash(user.password,form.password.data):
                    
                    login_user(user)
                    print(current_user.is_authenticated)
                    print(current_user.id)
                    posts = BlogPost.query.all()
                    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)
            else:
              flash('Incorrect Password')
              return render_template("login.html",form=form)
          else:
            flash('Entered email does not exit')
            return render_template("login.html",form=form)
    print(current_user.is_authenticated)
    return render_template("login.html",form=form,logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    posts = BlogPost.query.all()
    logout_user()
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['POST','GET'])
# @admin_only
@login_required
def add_new_post():
    form = CreatePostForm()
    id=current_user.id
    if request.method == "POST":
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            parent_id=id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
