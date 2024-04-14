from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "feedbacksecretkey123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def homepage():
    feedbacks = Feedback.query.limit(10).all()
    return render_template ('home.html', feedbacks=feedbacks)


@app.route('/register', methods = ['GET', 'POST'])
def register_user():
    """Renders register form and handles submission"""
    form = RegisterForm()

    #handles POST request
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        new_user = User.register(username, password, email, 
                                 first_name, last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken. Please enter another.')
            return render_template('register.html', form=form)

        session['username'] = new_user.username
        session['is_admin'] = new_user.is_admin
        flash('Welcome! Successfully Created Your Account!', 'primary')
        return redirect(f'/users/{new_user.username}')
    
    #responds to GET request with form
    return render_template('register.html', form=form)
    

@app.route('/login', methods = ['GET', 'POST'])
def login_user():
    """Renders login form and handles login authentication"""
    form = LoginForm()
    if form.validate_on_submit():
        username=form.username.data
        password=form.password.data
    
        user=User.login(username, password)
        if user:
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash(f'Welcome back, {user.full_name}!', 'primary')
            return redirect(f'/users/{user.username}')
        else:
            form.password.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)

@app.route('/logout')
def logout_user():
    session.pop('username')
    session.pop('is_admin')
    flash('Logged out', 'info')
    return redirect('/')


#************************** USER *****************************
@app.route('/users/<username>')
def user_page(username):
    """Renders user's page, with functionality only if authorized"""
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect ('/login')
    user = User.query.filter_by(username=username).first()
    return render_template('user.html', user=user)


@app.route('/users/<username>/delete', methods = ["GET", "POST"])
def delete_user(username):
    """Deletes user only if authorized"""
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect ('/login')
    
    user = User.query.filter_by(username=username).first()
    if user.username == session['username'] or session['is_admin'] == True:
        db.session.delete(user)
        db.session.commit()
        if user.username == session['username']:
            session.pop('username')
            session.pop('is_admin')
        flash('User deleted', 'info')
        return redirect ('/')
    
    flash("You don't have permission to do that", "danger")
    return redirect ('/')

#************************** FEEDBACK *****************************
@app.route('/users/<username>/feedback/add', methods = ['GET', 'POST'])
def add_feedback(username):
    """Renders feedback form only if user is authenticated & authorized
    and handles submission"""

    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect ('/login')
    
    form = FeedbackForm()
    user = User.query.filter_by(username=username).first()

    if form.validate_on_submit():
        title=form.title.data
        content=form.content.data
    
        feedback=Feedback(title=title, content=content, username=user.username)
        db.session.add(feedback)
        db.session.commit()

        flash(f'Feedback added', 'success')
        return redirect(f'/users/{username}')
    
    if user.username == session['username'] or session['is_admin'] == True:
        return render_template('feedback-form.html', 
                                form=form)
    
    flash("You don't have permission to do that", "danger")
    return redirect ('/')


@app.route('/feedback/<int:id>/update', methods = ['GET', 'POST'])
def edit_feedback(id):
    """Renders feedback edit form with authentication/authorization 
    and handles submission"""

    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect ('/login')
    
    feedback = Feedback.query.get_or_404(id)
    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data

        db.session.commit()
        
        flash(f'Feedback edited', 'info')
        return redirect (f'/users/{feedback.user.username}')
    
    if feedback.user.username == session['username'] or session['is_admin'] == True:
        return render_template('feedback-form.html', 
                                feedback=feedback,
                                form=form)
    flash("You don't have permission to do that", "danger")
    return redirect ('/')


@app.route('/feedback/<int:id>/delete', methods = ["GET", "POST"])
def delete_feedback(id):
    """Handles feedback deletion"""

    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect ('/login')
    
    feedback = Feedback.query.get_or_404(id)
    if feedback.user.username == session['username'] or session['is_admin'] == True:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted', 'info')
        return redirect (f'/users/{feedback.user.username}')
    
    flash("You don't have permission to do that", "danger")
    return redirect ('/')