
import os
import re

import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)


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
            self.redirect('/welcome?username=%s' % return_message['username_input'])

class WelcomeHandler(Handler):
    def get(self):
        username = self.request.get('username')
        self.render('welcome.html', username=username)


app = webapp2.WSGIApplication([
    ('/rot13', ROT13Handler),
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
], debug=True)
