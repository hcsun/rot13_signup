
import os
import re
import hashlib
import hmac

import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

from google.appengine.ext import db

from secret import SECRET
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_value(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_value(h):
    val = h.split('|')[0]
    if h == make_secure_value(val):
        return val

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

valid_user = re.compile("^[a-zA-Z0-9_-]{3,20}$")
valid_password = re.compile("^.{3,20}$")
valid_email = re.compile("^[\S]+@[\S]+.[\S]+$")

def ValidateUserInput(handle):
    return_message = {}

    username_input = handle.request.get('username')
    if not valid_user.match(username_input):
        return_message['username_error'] = "That's not a valid username."

    return_message['username_input'] = username_input

    password_input = handle.request.get('password')
    password_result = valid_password.match(password_input)
    if not password_result:
        return_message['password_valid_error'] = "That wasn't a valid password."

    verify_input = handle.request.get('verify')
    if password_result and password_input != verify_input:
        return_message['verify_error'] = "Your passwords didn't match."

    email_input = handle.request.get('email')
    if email_input and not valid_email.match(email_input):
        return_message['email_error'] = "That's not a valid email."

    return return_message

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class ROT13Handler(Handler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        user_text = self.request.get('text')
        rot13_str = Rot13_parsing(user_text)

        self.render('rot13.html', rot13=rot13_str)

class SignUpHandler(Handler):
    def get(self):
        # arg = {'username_error': 'user error', 'password_valid_error': 'password error'}
        self.render('signup.html')

    def post(self):
        return_message = ValidateUserInput(self)
        if len(return_message) > 1:
            self.render('signup.html', **return_message)
        else:
            user_id = make_secure_value(return_message['username_input'])
            self.response.headers.add_header('Set-Cookie', str("user_id=%s;Path=/" % user_id))
            self.redirect('/welcome')

class WelcomeHandler(Handler):
    def get(self):
        user_hash = self.request.cookies.get('user_id')
        username = check_secure_value(user_hash)

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
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/', MainPage),
], debug=True)
