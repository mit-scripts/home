#!/usr/bin/env python

import web
import re
import os

web.wsgi.runwsgi = lambda func, addr=None: web.wsgi.runfcgi(func, addr)

urls = (
	'/?', 'query',
	'/(.+)', 'lookup',
)

render = web.template.render('templates/')

class query(object):
	def GET(self, message=""):
		return render.layout(render.query(message))
	
	def POST(self):
		i = web.input()
		web.ctx.home = "/whois"
		web.redirect("/%s" % i.hostname)

class lookup(object):
	def GET(self, hostname=""):
		if not re.match('^[\w.-]+$', hostname):
			return query().GET("Bad request")
		output = "".join(os.popen('whois -h scripts.mit.edu %s' % (hostname), 'r').readlines()[2:])
		output = re.sub(r'Hostname: ([\w.-]+)\n', r'Hostname: <a href="http://\1">\1</a>\n', output)
		return render.layout(render.query(output))

if __name__ == "__main__":
	app = web.application(urls, globals())
	app.run()
