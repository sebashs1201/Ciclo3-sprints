from email.utils import format_datetime, formatdate
from multiprocessing import Value
from wsgiref.handlers import format_date_time
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, DateField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm

class RegisterForm(FlaskForm):
    identification=IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Identification"})
    username=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    email=EmailField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    born=DateField(validators=[InputRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    identification=IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Identification"})
    password=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class RoomForm(FlaskForm):
    codigo=IntegerField(validators=[InputRequired()], render_kw={"placeholder": "codigo de habitación"})
    submit = SubmitField("Save")

class ReservaForm(FlaskForm):
    checkin=DateField(validators=[InputRequired()])
    checkout=DateField(validators=[InputRequired()])
    people=IntegerField(validators=[InputRequired()], render_kw={"placeholder": "numero de personas"})
    submit = SubmitField("consultar")
