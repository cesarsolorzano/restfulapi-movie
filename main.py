#!/usr/bin/env python
import webapp2
import security, json, urllib
from webapp2_extras.appengine.auth import models
from google.appengine.ext import db
import base64

class Movies(db.Model):
    title = db.StringProperty(required=True);
    description = db.StringProperty(required=True);
    date_realese = db.StringProperty(required=True);
    user_created = db.StringProperty(required=True);
    poster_movie = db.BlobProperty();

def gql_json_parser(query_obj):
    result = []
    for entry in query_obj:
    	if entry.poster_movie:
    		poster = 'http://URl/img/'+str(entry.key())
    	else:
    		poster = None
    	dictionario = {'id':entry.key().id(),
    	'title' :entry.title,
    	'description' : entry.description,
    	'date_realese' : entry.date_realese,
    	'poster' : poster,
    	'user_id' : entry.user_created}
        result.append(dictionario)
    return result
#
#Api
#

def get_user(self):
	auth_header = self.request.headers.get('Authorization').split(" ")[1]
	e = models.UserToken.get(subject='TokenUser', token=auth_header)
	return e.user


class get_information(webapp2.RequestHandler):
    @security.token_requiered
    def get(self):
    	self.response.headers['Content-Type'] = 'application/json'   
    	self.response.out.write(json.dumps({  "meta": {"status": 200, "msg": "Ok"}, 'movies': gql_json_parser(Movies.all().fetch(100)) } ))


    @security.token_requiered
    def post(self):
    	#values = self.request.POST['values']
    	values = json.loads(self.request.body)
    	if not values:
    		abort(404)
    	else:
    		if values["poster"]:
	    		x = Movies(title= values["title"], 
	    			description=values["description"], 
	    			date_realese= str(values["date_realese"]), 
	    			user_created=str(get_user(self)),
	    			poster_movie=  db.Blob(base64.b64decode(values['poster'])), 
	    			)
	    	else:
	    		x = Movies(title= values["title"], 
	    			description=values["description"], 
	    			date_realese= str(values["date_realese"]), 
	    			user_created=str(get_user(self))
	    			)
    		x.put()
    		self.response.headers['Content-Type'] = 'application/json'   
    		self.response.out.write(json.dumps({ "meta": {"status": 201, "msg": "Created"}} ))
    		self.response.set_status(201)

class get_information_single(webapp2.RequestHandler):

	@security.token_requiered
	def get(self, ide):
		m = Movies.get_by_id(int(ide))
		if not m:
			self.abort(404)
		else:
			values={ "title": m.title, "description": m.description, "date_realese": m.date_realese, "id": m.key().id() }
			self.response.headers['Content-Type'] = 'application/json'   
			self.response.out.write(json.dumps({"meta": {"status": 200, "msg": "Ok"}, 'movies': values } ))

	@security.token_requiered
	def delete(self, ide):
		m = Movies.get_by_id(int(ide))
		if not m:
			self.abort(404)
		else:
			if get_user(self) == m.user_created:
				m.delete()
				self.response.headers['Content-Type'] = 'application/json' 
				self.response.out.write(json.dumps({ "meta": {"status": 200, "msg": "Ok"}, 'result': True } ))
			else:
				self.response.headers['Content-Type'] = 'application/json' 
				self.response.out.write(json.dumps({ "meta": {"status": 403, "msg": "Forbidden "}, 'result': False } ))
				self.response.set_status(403)

	@security.token_requiered
	def put(self, ide):
		values = json.loads(self.request.body)
		m = Movies.get_by_id(int(ide))
		if get_user(self) == m.user_created:
			if not m:
				self.abort(404)
			if not values:
				self.abort(404)
			m.title = values['title']
			m.description =values['description']
			m.date_realese = values['date_realese']
			if values["poster"]:
				m.poster_movie = db.Blob(base64.b64decode(str(values["poster"])))
			m.put()
			self.response.out.write(json.dumps({"meta": {"status": 200, "msg": "Ok"}, 'result': True } ))
		else:
			self.response.headers['Content-Type'] = 'application/json' 
			self.response.out.write(json.dumps({ "meta": {"status": 403, "msg": "Forbidden "}, 'result': False } ))
			self.response.set_status(403)

#
#Main
#
class MainHandler(security.BaseHandler):
	def get(self):
		security.render(self, "index.html")


class GetImage(webapp2.RequestHandler):
    def get(self, ide):
        try:
            x = db.get(ide)
            self.response.headers['Content-Type'] = 'image/jpeg'
            #self.response.headers['Cache-Control']  = 'public, max-age=315360000'
            self.response.out.write(x.poster_movie)
        except:
            self.error(404)


app = webapp2.WSGIApplication([
    webapp2.Route('/', handler=MainHandler),
	webapp2.Route('/signup', handler=security.CreateUserHandler, name='create-user'),
	webapp2.Route('/authorize', handler=security.LoginHandler, name='login'),
	webapp2.Route('/request_token', handler=security.request_token, name='create-token'),
	webapp2.Route('/api/v1.0/movies', handler=get_information),
    webapp2.Route('/api/v1.0/movies/<ide>', handler= get_information_single),
    webapp2.Route('/img/<ide>', handler= GetImage),
], debug=True, config=security.config)

#
# Erros
#

def handle_404(request, response, exception):
    response.out.write( json.dumps({  "meta": {"status": 404, "msg": "Not found"}}))
    response.headers['Content-Type'] = 'application/json'
    response.set_status(404)

def handle_401(request, response, exception):
	response.out.write( json.dumps({  "meta": {"status": 401,"msg": "Authorization Required"}}))
	response.headers['Content-Type'] = 'application/json'
	response.headers['WWW-Authenticate'] = 'Bearer realm="Secure area"'
	response.set_status(401)

def handle_403(request, response, exception):
	response.out.write( json.dumps({  "meta": {"status": 403,"msg": "Authorization Required"}}))
	response.headers['Content-Type'] = 'application/json'
	response.headers['WWW-Authenticate'] = 'Bearer realm="Secure area"'
	response.set_status(403)


app.error_handlers[404] = handle_404
app.error_handlers[401] = handle_401
app.error_handlers[403] = handle_403