import logging

from saml2 import BINDING_HTTP_REDIRECT

import ckan.plugins as p
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.model as model

import config.sp_config as config


log = logging.getLogger('ckanext.saml2')

class Saml2Plugin(p.SingletonPlugin):

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IRoutes, inherit=True)

    saml_identify = None

    def before_map(self, map):
        map.connect(
            'saml2_unauthorized',
            '/saml2_unauthorized',
            controller='ckanext.saml2.plugin:Saml2Controller',
            action='saml2_unauthorized'
        )
        return map

    def identify(self):
        ''' This does work around saml2 authorization.
        c.user contains the saml2 id of the logged in user we need to
        convert this to represent the ckan user. '''
        # Can we find the user?
        c = p.toolkit.c
        user = p.toolkit.request.environ.get('REMOTE_USER', '')
        if user:
            # we need to get the actual user info from the saml2auth client
            if not self.saml_identify:
                plugins = p.toolkit.request.environ['repoze.who.plugins']
                saml_client = plugins['saml2auth'].saml_client
                self.saml_identify = saml_client.users.get_identity
            saml_info = self.saml_identify(user)[0]

            # If we are here but no info then we need to clean up
            if not saml_info:
                base.response.delete_cookie('auth_tkt')
                h.redirect_to(controller='user', action='logged_out')

            c.user = saml_info['uid'][0]
            c.userobj = model.User.get(c.user)
            if c.userobj is None:
                # Create the user
                data_dict = {
                    'name': c.user,
                    'password': 'password',
                    'email': 'a@b.c',
                }
                for field in config.USER_MAPPING:
                    value = saml_info.get(config.USER_MAPPING[field])
                    if value:
                        # If list get first value
                        if isinstance(value, list):
                            value = value[0]
                        data_dict[field] = value
                user = p.toolkit.get_action('user_create')(None, data_dict)
                c.userobj = model.User.get(c.user)


    def login(self):
        # We can be here either because we are requesting a login (no user)
        # or we have just been logged in.
        if not p.toolkit.c.user:
            # A 401 HTTP Status will cause the login to be triggered
            return base.abort(401, p.toolkit._('Login required!'))
        h.redirect_to(controller='user', action='dashboard')


    def logout(self):
        environ = p.toolkit.request.environ
        # so here I might get either a LogoutResponse or a LogoutRequest
        client = environ['repoze.who.plugins']['saml2auth']
        sids = None
        if 'QUERY_STRING' in environ:
            try:
                client.saml_client.logout_request_response(
                    p.toolkit.request.GET['SAMLResponse'][0],
                    binding=BINDING_HTTP_REDIRECT)
            except KeyError:
                # return error reply
                pass

        if not sids:
            base.response.delete_cookie('auth_tkt')
            h.redirect_to(controller='user', action='logged_out')

    def abort(self, status_code, detail, headers, comment):
        # HTTP Status 401 causes a login redirect.  We need to prevent this
        # unless we are actually trying to login.
        if (status_code == 401
            and p.toolkit.request.environ['PATH_INFO'] != '/user/login'):
                h.redirect_to('saml2_unauthorized')
        return (status_code, detail, headers, comment)

class Saml2Controller(base.BaseController):

    def saml2_unauthorized(self):
        # This is our you are not authorized page
        c = p.toolkit.c
        c.code = 401
        c.content = p.toolkit._('You are not authorized to do this')
        return p.toolkit.render('error_document_template.html')
