
import os

import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)


def rot13_parsing(text):
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
        rot13_str = rot13_parsing(user_text)

        self.render('rot13.html', rot13=rot13_str)

app = webapp2.WSGIApplication([
    ('/rot13', ROT13Handler),
], debug=True)
