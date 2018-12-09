## Bradley Scharf
## SI 364 - Fall 2018
## Final

###############################
####### SETUP (OVERALL) #######
###############################

# Import statements
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from flask_script import Manager, Shell
from wtforms import StringField, SelectField, SubmitField, TextAreaField, PasswordField, BooleanField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.datastructures import MultiDict
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
import os
import requests
import json


## App setup code
app = Flask(__name__)
app.debug = True

## All app.config values
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgres://Bradley_Scharf@localhost/SI364Final"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

## App constants
API_KEY = "BPkzEWvcbWBgJMUSm95p3aEOPuPjmBRVcHSq0xhjsLgUZP5LfC0ukb9sW-ty5cS7OsXbjs-8XhHWr46mlRgvo6rFU22DZRSNkr4sYkckTnYsdcPhCAPw9peKxoPXW3Yx"
API_HOST = "https://api.yelp.com/"
DELIVERY_SEARCH = "v3/transactions/delivery/search"
BUSINESS_SEARCH = "v3/businesses/search"
BUSINESS = "restaurant"
headers = {'Authorization': f'Bearer {API_KEY}'}
SEARCH_LIMIT = 3

## Statements for db setup (and manager setup if using Manager)
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

###################
###### FORMS ######
###################

class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    location = StringField('Location:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z0-9 ,]*$',0,'Locations must be letters, or numbers(zip code)')])
    submit = SubmitField('Register User')

    #Additional checking methods for the form
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(user=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Required(), Length(1,64), Email()])
    password = PasswordField("Password", validators=[Required()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Log In")

class ReviewForm(FlaskForm):
    review = TextAreaField("Review:", render_kw={"rows": 11, "cols": 70},validators=[Required(), Length(min=0, max=7000)])
    submit = SubmitField("Submit")

class KeywordForm(FlaskForm):
    keyword = StringField("Search Businesses", validators=[Required()])
    submit = SubmitField('Submit')

    def validate_keyword(self,field):
        if len(field.data) <= 0:
            raise ValidationError("Blank data not accepted")

class UpdateReviewForm(FlaskForm):
    review = TextAreaField("Update Review:", render_kw={"rows": 11, "cols": 70},validators=[Required(), Length(min=0, max=7000)])
    update = SubmitField("Update")

class UpdateButtonForm(FlaskForm):
    update = SubmitField("Update")

class DeleteButtonForm(FlaskForm):
    delete = SubmitField("Delete")

##################
##### MODELS #####
##################

keyword_location = db.Table('keyword_location',
    db.Column("keyword_id", db.Integer, db.ForeignKey('keywords.id'), primary_key=True),
    db.Column("location_id", db.Integer, db.ForeignKey('locations.id'), primary_key=True)
)

keyword_business = db.Table('keyword_business',
    db.Column("keyword_id", db.Integer, db.ForeignKey('keywords.id'), primary_key=True),
    db.Column("business_id", db.String(255), db.ForeignKey('businesses.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"))
    reviews = db.relationship('Review', backref='owner')

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return "{} (ID: {})".format(self.user, self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Locations(db.Model):
    __tablename__ = "locations"
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(64))
    users = db.relationship('User', backref="location")

class Review(db.Model):
    __tablename__ = "review"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    restaurant_id = db.Column(db.String(100))
    restaurant_name = db.Column(db.String(100))
    review = db.Column(db.String(7000))

    def __repr__(self):
        return f"{self.restaurant_name} : {self.review}"

class Keywords(db.Model):
    __tablename__ = "keywords"
    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(128))
    locations = db.relationship('Locations', secondary=keyword_location, lazy="dynamic",
        backref=db.backref('keywords', lazy=True))
    businesses = db.relationship('Businesses', secondary=keyword_business, lazy="dynamic",
        backref=db.backref('keywords', lazy=True))

class Businesses(db.Model):
    __tablename__ = "businesses"
    id = db.Column(db.String(255), primary_key=True) #Set the ID based on Yelp's BusinessID
    name = db.Column(db.String(255))
    display_phone = db.Column(db.String(25))

    def __repr__(self):
        return f"{self.name} : {self.display_phone}"

#######################
##### HELPER FXNS #####
#######################
def get_or_create_location(location):
    l = Locations.query.filter_by(location=location).first()
    if not l:
        l = Locations(location=location)
        db.session.add(l)
        db.session.commit()
    return l

def get_yelp(lim, term):
    url = API_HOST + BUSINESS_SEARCH
    params = {
        'location': current_user.location.location,
        'limit': lim,
        'sort_by': 'rating',
        'term': term
    }
    return requests.get(url, headers=headers, params=params).json()['businesses']

def get_or_create_businesses(yelp):
    b = Businesses.query.filter_by(id=yelp['id']).first()
    if not b:
        b = Businesses(id=yelp['id'], name=yelp['name'], display_phone=yelp['display_phone'])
        db.session.add(b)
        db.session.commit()
    return b

def get_or_create_keyword(keyword):
    k = Keywords.query.filter_by(keyword=keyword).first()
    if not k:
        yelp = get_yelp(10, keyword)
        businesses = [get_or_create_businesses(y) for y in yelp]
        k = Keywords(keyword=keyword, businesses=businesses)
        current_user.location.keywords.append(k)
        db.session.add(k)
        db.session.commit()
    return k

#######################
###### VIEW FXNS ######
#######################

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('home'))
        flash('Invalid username or password.')
    return render_template("index.html", form=form)

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        loc = get_or_create_location(form.location.data)
        user = User(email=form.email.data,user=form.username.data,password=form.password.data, location=loc)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/home', methods=['GET'])
@login_required
def home():
    response = get_yelp(3, BUSINESS)
    return render_template("home.html", data=response)

@app.route('/review/<id>/<name>', methods=['GET', 'POST'])
@login_required
def review(id, name):
    form = ReviewForm()
    if request.method=="POST":
        review_obj = Review.query.filter_by(owner=current_user, restaurant_id=id).first()
        if not review_obj:
            review_obj = Review(owner=current_user, restaurant_id=id, restaurant_name=name, review=request.form.get("review"))
            db.session.add(review_obj)
            db.session.commit()
            flash("Review added for " + name)
        else:
            flash("Review already made for " + name)
        return redirect(url_for('my_reviews'))
    return render_template("review.html", form=form, id=id, name=name)

@app.route('/my_reviews')
@login_required
def my_reviews():
    formu = UpdateButtonForm()
    formd = DeleteButtonForm()
    all_reviews = Review.query.filter_by(owner=current_user)
    return render_template("review_read.html", all=all_reviews, formu=formu, formd=formd)

@app.route('/update/<review>',methods=["GET","POST"])
@login_required
def update(review):
    form = UpdateReviewForm()
    if form.validate_on_submit():
        updateReview = Review.query.filter_by(id=review).first()
        updateReview.review = form.review.data
        name = updateReview.restaurant_name
        db.session.commit()
        flash("Updated Review of " + name)
        return redirect(url_for('my_reviews'))
    return render_template('update_review.html', form=form, revID=review)

@app.route('/delete/<review>',methods=["GET","POST"])
@login_required
def delete(review):
    r = Review.query.filter_by(id=review)
    name = r.first().restaurant_name
    db.session.delete(r.first())
    db.session.commit()
    flash("Deleted review for " + name)
    return redirect(url_for('my_reviews'))

@app.route('/all_reviews')
@login_required
def all_reviews():
    results = Review.query.all()
    return render_template("all_review.html", results=results)

@app.route('/keywords', methods=['GET','POST'])
@login_required
def keywords():
    form = KeywordForm()
    if form.validate_on_submit():
        k = get_or_create_keyword(form.keyword.data)
        return redirect(url_for('businesses', keyword=form.keyword.data))
    return render_template('keywords.html', form=form)

@app.route('/businesses/<keyword>')
@login_required
def businesses(keyword):
    k = get_or_create_keyword(keyword)
    b = k.businesses
    return render_template('businesses.html', businesses=b, keyword=k.keyword)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 400

## Code to run the application...
if __name__ == '__main__':
    db.create_all() # Will create any defined models when you run the application
    app.run(use_reloader=True, debug=True) # The usual
