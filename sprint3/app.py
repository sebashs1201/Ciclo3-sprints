from email.policy import default
from xmlrpc.client import DateTime
from flask import Flask, render_template, url_for, redirect, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from settings.config import configuracion
from forms import LoginForm, RegisterForm, RoomForm, ReservaForm
from datetime import datetime

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config.from_object(configuracion)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    tipouser=db.Column(db.String(20), nullable=False, default='usuario_final')
    identification=db.Column(db.Integer, nullable=False, unique=True)
    username=db.Column(db.String(20), nullable=False, unique=True)
    password=db.Column(db.String(80), nullable=False)
    email=db.Column(db.String(20), nullable=False)
    born=db.Column(db.DateTime, nullable=False)

class Habitacion(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    codigo=db.Column(db.String(20), nullable=False, unique=True)
    estado=db.Column(db.Boolean, nullable=False)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        identification = User.query.filter_by(identification=form.identification.data).first()
        
        #print(usuario)
        if identification and bcrypt.check_password_hash(identification.password, form.password.data):
                login_user(identification)  
                session['usuario']=identification.username
                session['tipouser']=identification.tipouser
                if session['tipouser'] == 'usuario_final':
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('dashboardadmin'))
        else:
            flash('not registered')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/dashboardadmin', methods=['GET', 'POST'])
@login_required
def dashboardadmin():
    form = RoomForm() 
    rooms = Habitacion.query.all()
    return render_template('dashboardadmin.html', form=form, rooms=rooms)

@app.route('/dashboaradmin_crear_habitacion', methods=['POST'])
@login_required
def crear_habitacion():
    form = RoomForm() 
    if Habitacion.query.filter_by(codigo=form.codigo.data).first():
        flash('That room already exists. Please ingress a different one.')
        return redirect(url_for('dashboardadmin'))
    else:
        habitacion= Habitacion(codigo=form.codigo.data, estado=True)
        db.session.add(habitacion)
        db.session.commit()
        return redirect(url_for('dashboardadmin'))

@app.route('/borrar/<id>')
def borrarHabitacion(id):
    habitacion = Habitacion.query.filter_by(id=int(id)).delete()
    db.session.commit()
    return redirect(url_for('dashboardadmin'))

@app.route('/cambiarEstado/<id>')
def cambiarEstado(id):
    habitacion = Habitacion.query.filter_by(id=int(id)).first()
    habitacion.estado=not(habitacion.estado)
    db.session.commit()
    return redirect(url_for('dashboardadmin'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(identification=form.identification.data).first():
            flash('That username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user=User(identification=form.identification.data, username=form.username.data, password=hashed_password, email=form.email.data, born=form.born.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/reserva', methods=['GET', 'POST'])
def reserva():
    form = ReservaForm()
    #return redirect(url_for('reserva'))
    return render_template('reserva.html', form=form)

#def format_datetime(value, format="%d-%m-%Y"):
    #if value is None:
        #return ""
    #return datetime.strptime(str(value),"%Y-%m-%d").strftime(format)

#configured Jinja2 environment with user defined
#app.jinja_env.filters['date_format']=format_datetime

#@app.route("/fecha")
#def fecha():
    #data={'cdate':'2022-01-17'}
    #return render_template("fecha.html",row=data)

@app.route('/disponibilidad', methods=['GET', 'POST'])
def disponibilidad():
    form = ReservaForm()
    fecha = form.checkin
    
     
    rooms = Habitacion.query.filter_by(estado=True)
    #db.session.add(rooms)
    #db.session.commit()
    #return redirect(url_for('dashboardadmin'))
    return render_template('disponibilidad.html', rooms=rooms, fecha=fecha)
    #return 'disponibilidad'

if __name__=='__main__':
    app.run(debug=True, port=5000)