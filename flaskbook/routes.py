import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flaskbook import app, db, bcrypt, mail
from flaskbook.forms import RegistrationForm, LoginForm, UpdateProfileForm, PostForm, RequestResetForm, ResetPasswordForm
from flaskbook.modelss import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

@app.route("/")
@app.route("/home")
def home():
    stranica = request.args.get('pageee', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=stranica, per_page=2)
    return render_template('home.html', posts=posts)


@app.route("/registration", methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:           #kada smo ulogovani i kada kliknemo na registrate ili login nece nigde otici jer sa ovim govorimo da je trenutno ulogovan, tako isto i za def login
        return redirect(url_for('home'))
    formation = RegistrationForm()
    if formation.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(formation.password.data).decode('utf-8')
        user = User(usernamee=formation.username.data, emaill=formation.email.data, passwordd=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Your account has been created! You are now able to Login", 'success')
        return redirect(url_for('login'))
    return render_template('registration.html', title='Registration', form=formation)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    formation = LoginForm()
    if formation.validate_on_submit():
        user = User.query.filter_by(emaill=formation.email.data).first()
        if user and bcrypt.check_password_hash(user.passwordd, formation.password.data):
            login_user(user, remember=formation.remember.data)
            #next page sluzi kada smo izlogovani na stranici profile, vodi nas direktno na profil stranicu a ne na home kao sto je bilo. U sledeca dve linije koda to i objasnjava kako se to radi
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))  #if next_page znaci da if next_page is not None
        else:
            flash('Login Unsuccessful. Please check your email and password', 'danger')
    return render_template('login.html', title='Login', form=formation)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_image(form_image):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_image.filename)
    image_fn = random_hex + f_ext
    image_path = os.path.join(app.root_path, 'static/profile_pics', image_fn)

    output_size = (125, 125)
    i = Image.open(form_image)
    i.thumbnail(output_size)
    i.save(image_path)

    return image_fn


@app.route("/profile", methods=['GET', 'POST'])
@login_required                     #ovim kazemo da je potrebno da budes ulogovan kako bi odradio ovu funckiju
def profile():
    formation = UpdateProfileForm()
    #if sluzi da bi updejtovao username i email
    if formation.validate_on_submit():
        #if sluzi da bi postavili sliku
        if formation.image.data:
            image_file = save_image(formation.image.data)
            current_user.picture = image_file
        current_user.usernamee = formation.username.data
        current_user.emaill = formation.email.data
        db.session.commit()
        flash('Your profile has been updated.', 'success')
        return redirect(url_for('profile'))
    #elif sluzi da bi samo popunio polja sa trenutnim podatcima
    elif request.method == 'GET':
        formation.username.data = current_user.usernamee
        formation.email.data = current_user.emaill
    picturee = url_for('static', filename='profile_pics/' + current_user.picture)
    return render_template('profile.html', title='Profile', picturee=picturee, form=formation)


@app.route("/posts/new", methods=['GET', 'POST'])
@login_required
def new_post():
    formation = PostForm()
    if formation.validate_on_submit():
        poster = Post(titlee=formation.title.data, contentt=formation.content.data, author=current_user)
        db.session.add(poster)
        db.session.commit()
        flash('Your Post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', legend='New Post', form=formation)


@app.route("/posts/<int:post_idi>")
def postff(post_idi):
    postff = Post.query.get_or_404(post_idi)
    return render_template('every_post.html', title=postff.titlee, post=postff)


@app.route("/posts/<int:post_idi>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_idi):
    postff = Post.query.get_or_404(post_idi)
    if postff.author != current_user:
        abort(403)
    formation = PostForm()
    if formation.validate_on_submit():
        postff.titlee = formation.title.data
        postff.contentt = formation.content.data
        db.session.commit()
        flash("Your post has been updated", 'success')
        return redirect(url_for('postff', post_idi=postff.idd)) #obrati paznju da ovde se za post_idi = koristi postff.idd, jer je definisan sa postff = Post.query.get_or_404(post_idi), dok u html na stranici every_post se poziva post.idd direktno iz modelss.py
    elif request.method == 'GET':
        formation.title.data = postff.titlee
        formation.content.data = postff.contentt
    return render_template('create_post.html', title='Update Post', legend='Update Post', form=formation)

@app.route("/posts/<int:post_idi>/delete", methods=['POST'])
@login_required
def delete_post(post_idi):
    postic = Post.query.get_or_404(post_idi)
    if postic.author != current_user:
        abort(403)
    db.session.delete(postic)
    db.session.commit()
    flash('Your post has been deleted', 'success')
    return redirect(url_for('home'))



@app.route("/user/<string:usernammme>")
def user_posts(usernammme):
    stranica = request.args.get('pageee', 1, type=int)
    userko = User.query.filter_by(usernamee=usernammme).first_or_404()
    posts = Post.query.filter_by(author=userko).order_by(Post.date_posted.desc()).paginate(page=stranica, per_page=2)
    return render_template('user_posts.html', posts=posts, user=userko)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='orlicstefan1990@gmail.com', recipients=[user.emaill])
    msg.body = f'''To reset your password visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no chages will be made 
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    formation = RequestResetForm()
    if formation.validate_on_submit():
        user = User.query.filter_by(emaill=formation.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=formation)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    formation = ResetPasswordForm()
    if formation.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(formation.password.data).decode('utf-8')
        user.passwordd = hashed_password
        db.session.commit()
        flash("Your password has been updated! You are now able to log in", 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=formation)