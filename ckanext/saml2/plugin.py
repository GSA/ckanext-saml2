import logging
import uuid

from saml2 import BINDING_HTTP_REDIRECT

import ckan.plugins as p
import ckan.lib.base as base
import ckan.logic as logic
import ckan.lib.helpers as h
import ckan.model as model


log = logging.getLogger('ckanext.saml2')


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@logic.auth_sysadmins_check
def user_create(context, data_dict):
    msg = p.toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_update(context, data_dict):
    msg = p.toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class Saml2Plugin(p.SingletonPlugin):

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthFunctions, inherit=True)
    p.implements(p.IConfigurable)


    saml_identify = None
    rememberer_name = None

    def make_mapping(self, key, config):
        data = config.get(key)
        mapping = {}
        for item in data.split():
            bits = item.split('~')
            mapping[bits[0]] = bits[1]
        return mapping

    def configure(self, config):
        self.user_mapping = self.make_mapping('saml2.user_mapping', config)
        m = self.make_mapping('saml2.organization_mapping', config)
        self.organization_mapping = m

    def before_map(self, map):
        map.connect(
            'saml2_unauthorized',
            '/saml2_unauthorized',
            controller='ckanext.saml2.plugin:Saml2Controller',
            action='saml2_unauthorized'
        )
        return map

    def make_password(self):
        # create a hard to guess password
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

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
                saml_plugin = plugins.get('saml2auth')
                if not saml_plugin:
                    # saml2 repoze plugin not set up
                    return
                saml_client = saml_plugin.saml_client
                self.saml_identify = saml_client.users.get_identity
            saml_info = self.saml_identify(user)[0]

            # If we are here but no info then we need to clean up
            if not saml_info:
                self.delete_cookies()
                h.redirect_to(controller='user', action='logged_out')

            c.user = saml_info['uid'][0]
            c.userobj = model.User.get(c.user)
            if c.userobj is None:
                # Create the user
                data_dict = {
                    'name': c.user,
                    'password': self.make_password(),
                    'email': 'a@b.c',
                }
                self.update_data_dict(data_dict, self.user_mapping, saml_info)
                context = {'ignore_auth': True}
                user = p.toolkit.get_action('user_create')(context, data_dict)
                c.userobj = model.User.get(c.user)

                if self.organization_mapping['name'] in saml_info:
                    self.create_organization(saml_info)

    def create_organization(self, saml_info):
        org_name = saml_info[self.organization_mapping['name']][0]
        org = model.Group.get(org_name)

        context = {'ignore_auth': True}
        site_user = p.toolkit.get_action('get_site_user')(context, {})
        c = p.toolkit.c

        if not org:
            context = {'user': site_user['name']}
            data_dict = {
            }
            self.update_data_dict(data_dict, self.organization_mapping, saml_info)
            org = p.toolkit.get_action('organization_create')(context, data_dict)
            org = model.Group.get(org_name)

        # add membership
        member_dict = {
            'id': org.id,
            'object': c.userobj.id,
            'object_type': 'user',
            'capacity': 'member',
        }
        member_create_context = {
            'user': site_user['name'],
            'ignore_auth': True,
        }

        p.toolkit.get_action('member_create')(member_create_context, member_dict)


    def update_data_dict(self, data_dict, mapping, saml_info):
        for field in mapping:
            value = saml_info.get(mapping[field])
            if value:
                # If list get first value
                if isinstance(value, list):
                    value = value[0]
                if not field.startswith('extras:'):
                    data_dict[field] = value
                else:
                    if 'extras' not in data_dict:
                        data_dict['extras'] = []
                    data_dict['extras'].append(dict(key=field[7:], value=value))

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
            self.delete_cookies()
            h.redirect_to(controller='user', action='logged_out')

    def delete_cookies(self):
        if self.rememberer_name is None:
            plugins = p.toolkit.request.environ['repoze.who.plugins']
            saml_plugin = plugins.get('saml2auth')
            self.rememberer_name = saml_plugin.rememberer_name
        base.response.delete_cookie(self.rememberer_name)
        # We seem to end up with an extra cookie so kill this too
        domain = p.toolkit.request.environ['HTTP_HOST']
        base.response.delete_cookie(self.rememberer_name, domain='.' + domain)

    def abort(self, status_code, detail, headers, comment):
        # HTTP Status 401 causes a login redirect.  We need to prevent this
        # unless we are actually trying to login.
        if (status_code == 401
            and p.toolkit.request.environ['PATH_INFO'] != '/user/login'):
                h.redirect_to('saml2_unauthorized')
        return (status_code, detail, headers, comment)

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset,
        }


class Saml2Controller(base.BaseController):

    def saml2_unauthorized(self):
        # This is our you are not authorized page
        c = p.toolkit.c
        c.code = 401
        c.content = p.toolkit._('You are not authorized to do this')
        return p.toolkit.render('error_document_template.html')
