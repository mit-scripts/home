#!/usr/bin/env python

# TODO: Update shebang line to python3 when F20 servers are gone

import web
import re
import os
import ldap, ldap.filter
import posixpath

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
    def __init__(self):
        self.ldap_URL = ldap.get_option(ldap.OPT_URI)
        self.ldap = ldap.initialize(self.ldap_URL)
        self.ldap_base = ldap.get_option(ldap.OPT_DEFBASE)
        if not self.ldap_base:
            # TODO: Remove this when F20 servers are gone
            self.ldap_base = "dc=scripts,dc=mit,dc=edu"
        self.ldap_base = "ou=VirtualHosts,"+self.ldap_base

    def canonicalize(self, vhost):
        return vhost.lower().rstrip(".")
    def searchLDAP(self, vhost):
        attrlist = ('scriptsVhostName', 'scriptsVhostAlias', 'homeDirectory', 'scriptsVhostDirectory', 'uid')
        results = self.ldap.search_st(self.ldap_base, ldap.SCOPE_SUBTREE,
            ldap.filter.filter_format(
                '(|(scriptsVhostName=%s)(scriptsVhostAlias=%s))', (vhost,)*2),
                attrlist=attrlist, timeout=5)
        if len(results) >= 1:
            result = results[0]
            attrs = result[1]
            for attr in attrlist:
                attrs[attr] = ', '.join(list(map(lambda x: x.decode('utf8'), attrs[attr])))
            return attrs
        else:
            return None
    def getWhois(self, vhost):
        vhost = self.canonicalize(vhost)
        info = None
        tries = 0
        while (tries < 3) and not info:
            tries += 1
            try:
                info = self.searchLDAP(vhost)
                break
            except (ldap.TIMEOUT, ldap.SERVER_DOWN):
                self.ldap.unbind()
                self.ldap = ldap.initialize(self.ldap_URL)
        if info:
            info['docRoot'] = posixpath.join(info['homeDirectory'], 'web_scripts', info['scriptsVhostDirectory'])
            return """Hostname: <a href="http://%(scriptsVhostName)s">%(scriptsVhostName)s</a>
Alias: %(scriptsVhostAlias)s
Locker: %(uid)s
Document Root: %(docRoot)s""" % info
        elif tries == 3:
            return "The whois server is experiencing problems looking up LDAP records.\nPlease contact scripts@mit.edu for help if this problem persists."
        return "No such hostname"
    def GET(self, hostname=""):
        if not re.match('^[\w.-]+$', hostname):
            return query().GET("Bad request")
        output = self.getWhois(hostname)
        return render.layout(render.query(output))

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
