from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired, Length, Email

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=
                           [InputRequired(message="Username required"), 
                            Length(max=20, message="Username must be less than 20 characters")])
    
    password = PasswordField("Password", validators=
                             [InputRequired(message="Password required")])
    
    email = StringField("Email", validators=
                        [InputRequired(message="Email required"), 
                         Email(message="Please enter a valid email"),
                         Length(max=50, message="Email must be less than 50 characters")])
    
    first_name = StringField("First Name", validators=
                             [InputRequired(message="Please enter this field"),
                              Length(max=30, message="Name must be less than 30 characters")])
    
    last_name = StringField("Last Name", validators=
                            [InputRequired(message="Please enter this field"),
                             Length(max=30, message="Name must be less than 30 characters")])
    

class LoginForm(FlaskForm):
        username = StringField("Username", validators=
                           [InputRequired(message="Please enter your username")])
        password = PasswordField("Password", validators=
                             [InputRequired(message="Please enter your password")])
        

class FeedbackForm(FlaskForm):
        title = StringField("Title", validators=
                           [InputRequired(message="Please enter a title")])
        content = TextAreaField("Content", validators=
                             [InputRequired(message="Please enter some content")])