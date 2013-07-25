import webapp2, json
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

import logging
from webapp2_extras.appengine.auth import models
import jinja2, os
#Template information
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_environment = jinja2.Environment(autoescape=True, loader=jinja2.FileSystemLoader(template_dir))
def render(self, template, a = None):
    if not a:
        a = {}
    self.response.out.write(jinja_environment.get_template(template).render(a))


#Configuration
config = {}
config['webapp2_extras.sessions'] = {
        'secret_key': 'Set_this_to_something_random_and_unguessable',
    }
config['webapp2_extras.auth'] = {
'user_model': 'models.User',
}

#
# Decorators
#

def token_requiered(handler):
    """
    Decorator
    """
    def checking(self, *args, **kwargs):
        if not self.request.headers.get('Authorization'):
            self.abort(401)
        auth_header = self.request.headers.get('Authorization').split(" ")[1]
        e = models.UserToken.get(subject='TokenUser', token=auth_header)
        if not e:
            self.abort(401)
        else:
            return handler(self, *args, **kwargs)
    return checking


def user_required(handler):
    """
         Decorator for checking if there's a user associated with the current session.
         Will also fail if there's no session present.
     """
    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():
            # If handler has no login_url specified invoke a 403 error
            try:
                self.redirect(self.auth_config['login_url'], abort=True)
            except (AttributeError, KeyError), e:
                self.abort(403)
        else:
            return handler(self, *args, **kwargs)

    return check_login

class BaseHandler(webapp2.RequestHandler):
	"""
	BaseHandler for all requests
	Holds the auth and session properties so they are reachable for all requests
	"""
	def dispatch(self):
		"""
			Save the sessions for preservation across requests
		"""
		try:
			super(BaseHandler, self).dispatch()
		finally:
			self.session_store.save_sessions(self.response)

	@webapp2.cached_property
	def auth(self):
		return auth.get_auth()

	@webapp2.cached_property
	def session_store(self):
		return sessions.get_store(request=self.request)

	@webapp2.cached_property
	def auth_config(self):
		"""
		Dict to hold urls for login/logout
		"""
		return {
			'login_url': self.uri_for('login'),
			'logout_url': self.uri_for('logout')
		}


class CreateUserHandler(BaseHandler):
    def get(self):
        redirection = self.request.GET['redirect']
        token = self.request.GET['token']
        render(self, "signup.html", { 'redirection':redirection, 'token':token })

    def post(self):
    	"""
    	Get user and password with POST
    	"""
    	email = self.request.POST.get('email')
        password = self.request.POST.get('password')
        redirection = self.request.POST.get('redirect')
        token = self.request.POST.get('token')
        
        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL. If True ok, If False no new user is created
        user = self.auth.store.user_model.create_user(email, email_address = email, password_raw=password)
        if not user[0]: #user is a tuple
            self.redirect('/signup?error=1')
            return
        #else:
            # User is created, let's try redirecting to login page
        #    try:
        #        self.redirect(self.auth_config['login_url'], abort=True)
        #    except (AttributeError, KeyError), e:
        #        self.abort(403)
        
        if token:
            self.redirect('/authorize?redirect='+str(redirection))
        else:
            self.redirect('/')

import urllib, time
class request_token(BaseHandler):
    @user_required
    def get(self):
        redirection = self.request.GET['redirect']
        a = self.auth.get_user_by_session()
        user_id = str(a['user_id'])
        #t = db.GqlQuery("SELECT * FROM TokenRegister WHERE  id_user =:1", user_id).get()
        token = models.UserToken.create(user_id, 'TokenUser')
        time.sleep(4)
        self.redirect(uri=str(redirection)+"?token="+str(token.token))

class LoginHandler(BaseHandler):
    def get(self):
        redirection = self.request.GET['redirect']
        render(self, "login.html", {'auth':redirection})

    def post(self):
        username = self.request.POST.get('username')
        password = self.request.POST.get('password')
        try:
            self.auth.get_user_by_password(username, password)
            self.redirect('/request_token?redirect='+str(self.request.POST.get('redirect')))
        except (InvalidAuthIdError, InvalidPasswordError), e:
            self.redirect('/authentication')


