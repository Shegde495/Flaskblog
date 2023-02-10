# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField, BooleanField
# from wtforms.validators import DataRequired,EqualTo,Length,ValidationError
# from wtforms.validators import Email
# from app import USER,POST

# class RegistrationForm(FlaskForm):
#     username=StringField('username',validators=[DataRequired(),Length(min=4,max=20)])
#     email = StringField('email', validators=[DataRequired(), Email()])
#     password=PasswordField('password',validators=[DataRequired()])
#     confirm_password=PasswordField('confirm_password',validators=[DataRequired(),EqualTo('password')])
#     submit=SubmitField('Register')
    
#     def validate_username(self, username):
#         name=username.data
#         user=USER.query.filter_by(username=name).first()
#         if user:
#             raise ValidationError('Username already exists')
        
    
# class LoginForm(FlaskForm):
#     email = StringField('email', validators=[DataRequired(), Email()])
#     password=PasswordField('password',validators=[DataRequired()])
#     remember=BooleanField('remember me')
#     submit=SubmitField('Login')
    