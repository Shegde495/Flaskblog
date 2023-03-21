from flask import Flask, render_template, url_for,flash,redirect,request,abort
#from forms import RegistrationForm,LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_migrate  import Migrate
import bcrypt
from flask_login import LoginManager,UserMixin,login_user,current_user,logout_user,login_required
#from models import USER,POST
import secrets
import os
from PIL import Image
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail,Message

app = Flask(__name__)
app.config["SECRET_KEY"]='uhdbxdsjwxwsl'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///testing.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'shashu619shashu@gmail.com'
app.config['MAIL_PASSWORD'] = 'wurughwchxxmaoal'
db=SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
from datetime import datetime








class USER(db.Model,UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(20),unique=True,nullable=False)
    email=db.Column(db.String(20),unique=True,nullable=False)
    image=db.Column(db.String(20),nullable=True,default="default.jpg")
    password=db.Column(db.String(20),nullable=False)
    post_by_user=db.relationship('POST',backref="author",lazy=True)
    
    
    def __repr__(self):
        return f"user('{self.username},{self.email},{self.image}')"
    
    def reset_password(self):#called by obj
        s=Serializer(app.config["SECRET_KEY"])
        user_id={'user_id':self.id}
        token=s.dumps(user_id)
        return token
    
    @staticmethod#called by class
    def set_password(token):
        s=Serializer(app.config["SECRET_KEY"])
        try:
            user_id=s.loads(token)['user_id']
        except:
           return None
        return USER.query.get(user_id)
    
class POST(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(20),nullable=False)
    created=db.Column(db.DateTime,nullable=False,default=datetime.utcnow())
    text=db.Column(db.Text,nullable=False)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),nullable=False)
    
    def __repr__(self):
        return f"post('{self.id},{self.title},{self.text}')"
    
    
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField,TextAreaField
from wtforms.validators import DataRequired,EqualTo,Length,ValidationError
from wtforms.validators import Email
from flask_wtf.file import FileField,FileAllowed


class RegistrationForm(FlaskForm):
    username=StringField('username',validators=[DataRequired(),Length(min=4,max=20)])
    email = StringField('email', validators=[DataRequired(), Email()])
    password=PasswordField('password',validators=[DataRequired()])
    confirm_password=PasswordField('confirm_password',validators=[DataRequired(),EqualTo('password')])
    submit=SubmitField('Register')
    
    def validate_username(self, username):
        name=username.data
        user=USER.query.filter_by(username=name).first()
        if user:
            raise ValidationError('Username already exists')
        
    def validate_email(self, email):
        email=email.data
        user=USER.query.filter_by(email=email).first()
        if user:
            raise ValidationError('email already exists')
        
    
class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password=PasswordField('password',validators=[DataRequired()])
    remember=BooleanField('remember me')
    submit=SubmitField('Login')
    
    
class Updateform(FlaskForm):
    username=StringField('username',validators=[DataRequired(),Length(min=4,max=20)])
    email = StringField('email', validators=[DataRequired(), Email()])
    picture=FileField('Update Profile',validators=[FileAllowed(['jpg','png'])])
    submit=SubmitField('Update')
    
    def validate_username(self, username):
        name=username.data
        if name!=current_user.username:
            user=USER.query.filter_by(username=name).first()
            if user:
                raise ValidationError('Username already exists')
        
    def validate_email(self, email):
        email=email.data
        if email !=current_user.email:
            user=USER.query.filter_by(email=email).first()
            if user:
                raise ValidationError('email already exists')
    
class PostForm(FlaskForm):
    title=StringField('title',validators=[DataRequired()])
    content=TextAreaField('content',validators=[DataRequired()])
    submit=SubmitField('Post')
    
class EmailverifyForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    submit=SubmitField('Verify email')
    
    def validate_email(self, email):
        user=USER.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Email not found')
        
class PasswordchangeForm(FlaskForm):
    password=PasswordField('password',validators=[DataRequired()])
    confirm_password=PasswordField('confirm_password',validators=[DataRequired(),EqualTo('password')])
    submit=SubmitField('Change Password')
     


login_manager = LoginManager(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(id):
    return USER.query.get(int(id))

    
    
    
    
# posts = [
#     {
#         'author': 'Corey Schafer',
#         'title': 'Blog Post 1',
#         'content': 'First post content',
#         'date_posted': 'April 20, 2018'
#     },
#     {
#         'author': 'Jane Doe',
#         'title': 'Blog Post 2',
#         'content': 'Second post content',
#         'date_posted': 'April 21, 2018'
#     }
# ]


@app.route("/")
@app.route("/home")
def home():
    value=request.args.get('page',1,type=int)
    posts=POST.query.order_by('created').paginate(page=value,per_page=2)
    return render_template('home.html', posts=posts)


@app.route("/about")
def about():
    print(current_user)
    return render_template('about.html', title='About')

@app.route("/register",methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RegistrationForm()
    if form.validate_on_submit():
        password=form.password.data.encode('utf-8')
        hashed_password=bcrypt.hashpw(password,bcrypt.gensalt())
        print(hashed_password)
        user=USER(username=form.username.data, password=hashed_password.decode('utf-8'),email=form.email.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created successfuly {form.username.data}','success')   
        return redirect(url_for('register'))
    return render_template("register.html", form=form)

@app.route("/login",methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=LoginForm()
    if form.validate_on_submit():
        user = USER.query.filter_by(email=form.email.data).first()
        #user=USER.query.filter_by(email=form.email.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
             flash(f'Logined successfuly {form.email.data}','success')  
             login_user(user)
             return redirect(url_for('home'))
        else:
            flash('Username or password is incorrect')
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(image):
    random_hex=secrets.token_hex(8)
    print(random_hex)
    f_name,f_ext=os.path.splitext(image.filename)
    new_name=random_hex+f_ext
    picture_path = os.path.join(app.root_path,'static/profile_pics',new_name)
    image.save(picture_path)
    # output_size=(125,125)
    # i=Image.open(image)
    # i.thumbnail(output_size)
    # i.save(picture_path)
    return new_name
    
    
@app.route("/account",methods=['GET','POST'])
@login_required
def account():
    form=Updateform()
    images=url_for('static',filename='profile_pics/'+current_user.image)
    if form.validate_on_submit():
        if form.picture.data:      
            pic=form.picture.data
            profile_pic=save_picture(pic)
            current_user.image=profile_pic
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    #data={'images':images,'form':form}
    return render_template("account.html",images=images,form=form)
    
    
@app.route("/post",methods=['GET','POST'])
@login_required
def post():
    form=PostForm()
    if form.validate_on_submit():
        post=POST(title=form.title.data,text=form.content.data,user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash(f'Successfully created a new post!', 'success')
        return redirect(url_for('home'))
    return render_template("post.html",form=form,name="Create")
# @app.route("/login", methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         if form.email.data == 'admin@blog.com' and form.password.data == 'password':
#             flash('You have been logged in!', 'success')
#             return redirect(url_for('home'))
#         else:
#             flash('Login Unsuccessful. Please check username and password', 'danger')
#     return render_template('login.html', title='Login', form=form)


@app.route("/post/<int:id>", methods=['GET'])
@login_required
def post_with_id(id):
    post=POST.query.get_or_404(id)
    return render_template("view_post.html",post=post)

@app.route("/update/<int:id>", methods=['GET', 'POST'])
@login_required
def update(id):
    form=PostForm()
    post=POST.query.get_or_404(id)
    if current_user.username!=post.author.username:
        abort(403)
    if form.validate_on_submit():
        post.title=form.title.data
        post.text=form.content.data
        db.session.commit()
        flash(f'Successfully updated','success')
        return redirect(url_for('post_with_id',id=post.id))
    else:
        form.title.data=post.title
        form.content.data=post.text    
    return render_template("post.html",post=post,name="Update",form=form)
    
@app.route("/delete/<int:id>", methods=['POST'])
@login_required
def delete(id):
    post=POST.query.get_or_404(id)
    if current_user.username!=post.author.username:
        abort(403)
    else:
        db.session.delete(post)
        db.session.commit()
        flash(f'Successfully deleted','success')
        return redirect(url_for('home'))
    
def send_email(user,value):
    msg = Message(
        subject='Test Email',
        recipients=[user.email],
        sender=app.config['MAIL_USERNAME'],
        body=f'Your reset link is' + value
    )
    mail.send(msg)
    
@app.route('/userpage/<string:username>')
def userpage(username):
    value=request.args.get('page',1,type=int)
    user=USER.query.filter_by(username=username).first_or_404()
    posts=POST.query.filter_by(user_id=user.id)\
        .order_by('created')\
        .paginate(page=value,per_page=2)
    return render_template('user_profile.html', posts=posts,user=user)

    
@app.route("/emailverify",methods=['GET','POST'])
def emailreset():
    form=EmailverifyForm()
    if form.validate_on_submit():
        user=USER.query.filter_by(email=form.email.data).first()
        value='http://127.0.0.1:5000/reset_password/'+str(user.reset_password())
        send_email(user,value)
        flash(f'Reset link has been sent to your email address.', 'success')
        return redirect(url_for('emailreset') )
    return render_template('email.html',title='Reset-password',form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user=USER.set_password(token)
    if user is None:
        flash(f'Token is expired. Please try again.','warning')
        return redirect(url_for('emailreset') )
    form=PasswordchangeForm()
    if form.validate_on_submit():
        password=bcrypt.hashpw(form.password.data.encode('utf-8'),bcrypt.gensalt())
        user.password=password.decode('utf-8')
        db.session.commit()
        return redirect(url_for('login'))   
    return render_template('reset_password.html',form=form)

@app.errorhandler(404)
def error_404(e):
    return render_template('error404.html'),404
    

if __name__ == '__main__':
    app.run(debug=True)
    
    
    
    {
    "openapi": "3.0.0",
    "info": {
      "version": "1.0.0",
      "title": "Bookmark Api "
    },
    "components": {
      "securitySchemes": {
        "bearerAuth": {
          "type": "http",
          "scheme": "bearer",
          "bearerFormat": "JWT"
        }
      }
    },
   

    "tags": [
    {
      "name": "List of actions",
      "description": "Flask API"
    }
  ],
  "servers": [
    {
    "url": "/"
    }
],
"paths": {
  "/api": {
      "post": {
      "tags": [
          "Registration"
      ],
      "summary": "Register",
      "requestBody": {
      "description": "Register",
      "required": true,
      "content": {
          "application/json": {
            "schema": {
              "type": "object",
              "properties": {
                  "username": {
                  "type": "string"
                  },
                  "email": {
                  "type": "string"
                  },
                  "password":{
                      "type": "string"
                  },
                  "password_confirmation":{
                      "type": "string"
                  }
              }
              }
              }
          }
      },
      "responses": {
          "200": {
              "description": "OK"
              }
          },
          "404": {
              "description": "NOT FOUND"
      }
      }
      },
      "/api/login":{
        "post": {
          "tags": [
              "LOGIN"
          ],
          "summary": "Login form",
          "requestBody": {
          "description": "Login",
          "required": true,
          "content": {
              "application/json": {
              "schema": {
                  "type": "object",
                  "properties": {
                      "email": {
                      "type": "string"
                      },
                      "password":{
                          "type": "string"
                      }
                    }
                  }}}},
                  "responses": {
                      "200": {
                          "description": "OK"
                          }
                      },
                      "404": {
                          "description": "NOT FOUND"
                  }
                }},
 "/api/bookmark":
                {
                  "get": {
                    "tags": [
                        "Bookmarks"
                    ],
                    "security": [
                      {
                        "bearerAuth": []
                      }
                    ],
                    "summary": "books",
                    "requestBody": {
                    "content": {
                        "application/json": {
                       }}},
                            "responses": {
                                "200": {
                                    "description": "OK"
                                    }
                                },
                                "404": {
                                    "description": "NOT FOUND"
                            }
                          },
                    "post":{
                      "tags":[
                        "Bookmarks"
                      ],
                      "security": [
                        {
                          "bearerAuth": []
                        }
                      ],
                    "summary": "Adding new bookmarks",
                      "requestBody":{
                        "content":{
                          "application/json":{
                            "schema": {
                              "type": "object",
                              "properties": {
                                  "body": {
                                  "type": "string"
                                  }
                                }
                              }

                          }
                        }
                      },
                      
                      "responses": {
                        "200": {
                            "description": "OK"
                            }
                        },
                        "404": {
                            "description": "NOT FOUND"
                    }


                    }
                        
                        },
                        "/api/bookmark/{id}":{

                          "get" :{
                              "tags": [
                                  "Get todos from API"
                              ],
                              "summary": "Get todos",
                              "parameters": [{
                                "name": "id",
                                "in": "path",
                                "description": "bookmarks id to update",
                                "required": true,
                                "type": "integer"
                              }],
                              "security": [
                                {
                                  "bearerAuth": []
                                }
                              ],
                              "responses": {
                              "200": {
                                  "description": "OK"
                              },
                              "404": {
                                  "description": "NOT FOUND"
                                  }
                          }
                          }
                          }                         
                
                
                
                
                
                
                        }}


    