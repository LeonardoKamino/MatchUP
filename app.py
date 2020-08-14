import os

import sqlite3
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from helpers import apology, login_required
from os.path import join, dirname, realpath
import string

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
PROFILE_PICTURES_FOLDER = join(dirname(realpath(__file__)), 'static/profilepics')
POST_PICTURES_FOLDER = join(dirname(realpath(__file__)), 'static/postpics')


# Configure application
app = Flask(__name__)
app.config['PROFILE_PICTURES_FOLDER'] = PROFILE_PICTURES_FOLDER
app.config['POST_PICTURES_FOLDER'] = POST_PICTURES_FOLDER

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
conn = sqlite3.connect('general.db', check_same_thread=False)
db = conn.cursor()

@app.route("/")
def index():

    return render_template('index.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          (request.form.get("username"),))
        rows = list(rows)
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][4], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/home")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

#check if file is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        first_name = string.capwords(request.form.get("first_name"))
        last_name = string.capwords(request.form.get("last_name"))
        file = request.files['file']
        filename = ""
        #check if username input is valid
        rows = db.execute("SELECT * FROM users WHERE username = ?",      
                            (username,))
        rows = list(rows)

        if len(rows) != 0 or username == "":
            return apology("Invalid Username")
        if first_name == "" or last_name == "":
            return apology("Missing names")
        #check if passwords and confirmation inputs are blank
        if password == "" or confirmation == "":
            return apology("Missing Password")

        #check if password and confirmation matchs
        if password != confirmation:
            return apology("Passwords doesn't match")
        #add user to database
        db.execute("INSERT INTO users (username, hash, first_name, last_name) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), first_name, last_name))
        conn.commit()

        #discover user id
        user = db.execute("SELECT * FROM users WHERE username = ?",
                            (username, ))
        user_id = list(user)[0][0]
        #save uploaded photo to server
        if file and allowed_file(file.filename) and file.filename != '':
            filename = secure_filename(file.filename)
            extension = filename.split(".")[-1]
            filename = str(user_id) + "." + extension
            file.save(os.path.join(app.config['PROFILE_PICTURES_FOLDER'], filename))
            db.execute("UPDATE users SET photo = ? WHERE username = ?",
                        (filename, username))
            conn.commit()


        return redirect('/login')
    else:
        return render_template('register.html')


#allow user to chang password
@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():
    if request.method == 'GET':
        return render_template('changepass.html')
    else:
        user_id = session.get("user_id")
        oldpassword = request.form.get("oldpassword")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE id = ?",
                          (user_id))

        #check if passwords and confirmation inputs are blank
        if password == "" or confirmation == "" or oldpassword == "":
            return apology("Missing Password")
        #check if provided oldpassword matchs with database
        if not check_password_hash(rows[0]["hash"], oldpassword):
            return apology("Old password is incorrect")

        #check if password and confirmation matchs
        if password != confirmation:
            return apology("New Passwords don't match")
        db.execute('UPDATE users SET hash = ? WHERE id = ?',
                    (generate_password_hash(password), user_id))
        conn.commit()
        return redirect('/profile')

#main page of website
@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "GET":
        return render_template("home.html")

    else:
        province = request.form.get("province")
        return redirect(url_for('posts', province=province))


@app.route("/posts", methods=["GET", "POST"])
@login_required
def posts():
    if request.method == "GET":
        province= request.args.get('province', None)
        posts = db.execute("""SELECT posts.post_id, posts.title, posts.description, posts.category, 
                                posts.email, posts.phone, posts.city, posts.province, posts.photo,
                                users.username 
                                FROM posts 
                                JOIN users ON posts.creator_id = users.id 
                                WHERE posts.province = ? 
                                ORDER BY post_id DESC;""",
                                (province, ))
        posts = list(posts)
        return render_template("posts.html", province=province, posts=posts)



#creation of new post
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        return(render_template("createpost.html"))
    else:
        title = request.form.get("title")
        description = request.form.get("description")
        province = request.form.get("province")
        city = request.form.get("city")
        email = request.form.get("email")
        phone = request.form.get("phone")
        user_id = session.get("user_id")
        category = request.form.get("category")
        file = request.files['file']
        filename = ''

        #check if phone is null
        #others variables are not nul because we garantee it with html
        if phone == '':
            phone= None

        #add new post to db
        db.execute("INSERT INTO posts (creator_id, title, description, province, city, email, phone, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (user_id,title, description, province, city, email, phone, category))
        conn.commit()
        #discover the post_id for this newpost
        post = db.execute("SELECT * FROM posts WHERE creator_id = ? and title = ? and city = ?",
                    (user_id, title, city))
        post_id = list(post)[0][0]

        #save uploaded photo to server
        if file and allowed_file(file.filename) and file.filename != '':
            filename = secure_filename(file.filename)
            extension = filename.split(".")[-1]
            filename = str(post_id) + "." + extension
            file.save(os.path.join(app.config['POST_PICTURES_FOLDER'], filename))

        #set filename to default if no photo was uploaded
        else:
            filename = 'postdefault.png'

        print(filename)
        #insert correct name of photo in db
        db.execute("UPDATE posts SET photo = ? WHERE post_id = ?",
                    (filename, post_id))
        conn.commit()

        return redirect('/home')


#show user his own profile
@app.route("/myprofile", methods=["GET", "POST"])
@login_required
def myprofile():
    if request.method == 'GET':
        user_id = session.get("user_id")
        user = db.execute("SELECT * FROM users WHERE id = ?",
                        (user_id,))
        user=list(user)
        posts = db.execute("SELECT * FROM posts WHERE creator_id = ? ORDER BY post_id DESC",
                            (user_id,))
        posts=list(posts)
        return render_template('myprofile.html', user=user[0], posts=posts)                


#allow user to edit the profile information
@app.route("/editprofile", methods=["GET", "POST"])
@login_required
def editprofile():
    if request.method == 'GET':
        user_id = session.get("user_id")
        user = db.execute("SELECT * FROM users WHERE id = ?",
                        (user_id,))
        user = list(user)
        return render_template('editprofile.html', user=user[0])    
    else:
        user_id = session.get("user_id")
        username = request.form.get("username")
        first_name = string.capwords(request.form.get("first_name"))
        last_name = string.capwords(request.form.get("last_name"))
        file = request.files['file']
        filename = ""

        #update username
        if username != "":
            db.execute("UPDATE users SET username=? WHERE id=?",
                    (username, user_id))

        #update first name
        if first_name != "":
            db.execute("UPDATE users SET first_name=? WHERE id=?",
                        (first_name, user_id))
        
        #update last name
        if first_name != "":
            db.execute("UPDATE users SET last_name=? WHERE id=?",
                        (last_name, user_id))
        
        #update image
        if file.filename != "":
            user = db.execute("SELECT * FROM users WHERE id = ?",
                            (user_id,))
            user = list(user)
            #delete previous photo
            path = os.path.join(app.config['PROFILE_PICTURES_FOLDER'], user[0][5])
            if os.path.exists(path):
                os.remove(path)

            #save new photo
            if file and allowed_file(file.filename) and file.filename != '':
                filename = secure_filename(file.filename)
                extension = filename.split(".")[-1]
                filename = str(user[0][0]) + "." + extension
                file.save(os.path.join(app.config['PROFILE_PICTURES_FOLDER'], filename))

            #update db
            db.execute("UPDATE users SET photo=? WHERE id=?",
                        (filename, user_id))
        conn.commit()
        return redirect('/myprofile')
        

#check if username is in db
@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("q")
    rows = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    rows = list(rows)
    if len(rows) == 1 and rows[0][0] != session.get("user_id"):
        return jsonify(response="False")
    else:
        return jsonify(response="True")


#delete post
@app.route("/deletepost", methods=["POST"])
@login_required
def deletepost():
    post_id = request.form['delete_button']

    #delete post photo from server
    post = db.execute("SELECT * FROM posts WHERE post_id=?",
                        (post_id, ))
    post = list(post)
    path = os.path.join(app.config['POST_PICTURES_FOLDER'], post[0][8])
    if os.path.exists(path):
        os.remove(path)

    #delete post from
    db.execute("DELETE FROM posts WHERE post_id=?",
                (post_id, ))
    conn.commit()
    return redirect("/myprofile")


@app.route("/getpost", methods=["POST"])
@login_required
def getpost():
    post_id = request.form['post_id']       
    post = db.execute("SELECT * FROM posts WHERE post_id = ?",
                    (post_id, ))
    post = list(post)
    return redirect(url_for('editpost', post=post[0][0]))  


@app.route("/editpost", methods=["POST", "GET"])
@login_required
def editpost():
    if request.method == "GET":
        post_id = request.args.get('post', None)
        post = db.execute("SELECT * FROM posts WHERE post_id=?",
                            (post_id, ))
        post = list(post)
        if post[0][1] != session.get("user_id"):
            redirect('/')
        
        return render_template('editpost.html', post=post[0])


    else:
        title = request.form.get("title")
        description = request.form.get("description")
        province = request.form.get("province")
        city = request.form.get("city")
        email = request.form.get("email")
        phone = request.form.get("phone")
        post_id = request.form.get("post_id")
        category = request.form.get("category")
        file = request.files['file']
        filename = ''  

        post = db.execute("SELECT * FROM posts WHERE post_id = ?",
                            (post_id, ))
        post = list(post)[0]

        if title != '' and title != post[2]:
            db.execute('UPDATE posts SET title = ? WHERE post_id = ?',
                        (title, post_id))
        
        if description != '' and description != post[3]:
            db.execute('UPDATE posts SET description = ? WHERE post_id = ?',
                        (description, post_id))
        
        if province != "" and province != post[4]:
            db.execute('UPDATE posts SET province = ? WHERE post_id = ?',
                        (province, post_id))
        
        if city != '' and city != post[5]:
            db.execute('UPDATE posts SET city = ? WHERE post_id = ?',
                        (city, post_id))
        
        if email != '' and email != post[6]:
            db.execute('UPDATE posts SET email = ? WHERE post_id = ?',
                        (email, post_id))

        if phone != '' and phone != post[7]:
            db.execute('UPDATE posts SET phone = ? WHERE post_id = ?',
                        (phone, post_id))

        if category != '' and category != post[8]:
            db.execute('UPDATE posts SET category = ? WHERE post_id = ?',
                        (category, post_id))

        if file.filename != "":
            #delete previous photo
            path = os.path.join(app.config['POST_PICTURES_FOLDER'], post[8])
            if os.path.exists(path):
                os.remove(path)

            #save new photo
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                extension = filename.split(".")[-1]
                filename = str(post[0]) + "." + extension
                file.save(os.path.join(app.config['POST_PICTURES_FOLDER'], filename))

            #update db
            db.execute("UPDATE posts SET photo=? WHERE post_id=?",
                        (filename, post_id))
        conn.commit()
        return redirect('/myprofile')

@app.route("/profile")
@login_required
def profile():
    username = request.args.get('username', None)

    user = db.execute("SELECT * FROM users WHERE username = ?",
                    (username,))
    user=list(user)
    user_id = user[0][0]

    posts = db.execute("SELECT * FROM posts WHERE creator_id = ? ORDER BY post_id DESC",
                        (user_id,))
    posts=list(posts)
    return render_template('profile.html', user=user[0], posts=posts)      

@app.route("/getprofile", methods=["POST"])
@login_required
def getprofile():

    username = request.form['creator_username'] 
    return redirect(url_for('profile', username=username))


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)



