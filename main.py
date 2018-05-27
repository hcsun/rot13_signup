
import hashlib
import hmac
import os
import random
import re
import string

from google.appengine.ext import db
import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)



from secret import SECRET
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_value(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_value(h):
    val = h.split('|')[0]
    if h == make_secure_value(val):
        return val

def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in range(length))

def make_pw_hash(name, pw, salt=make_salt()):
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)

def UserKey(group='default'):
    return  db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = UserKey())

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name = ', name).get()

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = UserKey(), name = name, pw_hash = pw_hash, email = email)
   
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_value(val)
        self.response.headers.add_header(
            'Set-Cookie', 
            str('%s=%s;Path=/' % (name, cookie_val)))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_value(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def Rot13_parsing(text):
    rot13_str = ""
    for c in text:
        if c.isalpha():
            if c.islower():
                char_num = ord(c) - 97
                char_num = (char_num + 13) % 26 + 97
            else:
                char_num = ord(c) - 65
                char_num = (char_num + 13) % 26 + 65

            rot13_str += chr(char_num)
        
        else:
            rot13_str += c

    return rot13_str

class ROT13Handler(Handler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        user_text = self.request.get('text')
        rot13_str = Rot13_parsing(user_text)

        self.render('rot13.html', rot13=rot13_str)


valid_user = re.compile("^[a-zA-Z0-9_-]{3,20}$")
valid_password = re.compile("^.{3,20}$")
valid_email = re.compile("^[\S]+@[\S]+.[\S]+$")

class SignUpHandler(Handler):
    def get(self):
        # arg = {'username_error': 'user error', 'password_valid_error': 'password error'}
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

        if not valid_user.match(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        password_result = valid_password.match(self.password)
        if not password_result:
            params['password_valid_error'] = "That wasn't a valid password."
            have_error = True

        if password_result and self.password != self.verify:
            params['verify_error'] = "Your passwords didn't match."
            have_error = True

        if self.email and not valid_email.match(self.email):
            params['email_error'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class SimpleSignUP(SignUpHandler):
    def done(self):
        self.redirect('welcome.html', username = self.username)

class Register(SignUpHandler):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = "That user already exist!"
            self.render('signup.html', username_error = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.render('welcome.html', username = self.username)


class WelcomeHandler(Handler):
    def get(self):
        username = self.request.get('username')

        if username:
            if valid_user.match(username):
                self.render('welcome.html', username=username)
                return

        self.redirect('/signup')



def BlogKey(name = "default"):
    return db.Key.from_path('blogs', name)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self)


class BlogFront(Handler):
    def get(self):
        posts = db.GqlQuery('select * from Post order by created desc limit 10')
        self.render('front.html', posts=posts)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=BlogKey())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post=post)

class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = BlogKey(), subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Wrong Subject or Content'
            self.render("newpost.html", subject=subject, content=content, error=error)

class MainPage(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        
        visits = 0
        
        visits_str = self.request.cookies.get('visits')
        if visits_str:
            val = check_secure_value(visits_str)
            if val:
                visits = int(val)

        visits += 1

        visits_encode = make_secure_value(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s' % visits_encode)

        self.write("You've been here %s times!" % visits)

app = webapp2.WSGIApplication([
    ('/rot13', ROT13Handler),
    ('/simple/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/signup', Register),
], debug=True)
