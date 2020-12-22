import logging
import uuid
from saml2 import BINDING_HTTP_REDIRECT
from ckan.common import _, request
import pylons.config as config

import ckan.plugins as p
import ckan.lib.base as base
import ckan.logic as logic
import ckan.lib.helpers as h
import ckan.model as model
import urlparse
import ckan.logic.schema as schema
from importlib import import_module
from ckan.controllers.user import UserController
from routes.mapper import SubMapper
from saml2.ident import decode as unserialise_nameid
from saml2.s2repoze.plugins.sp import SAML2Plugin
from ckan.logic.action.create import _get_random_username_from_email
from ckanext.saml2.model.saml2_user import SAML2User
from sqlalchemy.sql.expression import or_
from sqlalchemy import func
from ckan.logic.action.delete import user_delete as ckan_user_delete
from ckan.logic.action.update import user_update as ckan_user_update


log = logging.getLogger('ckanext.saml2')
DELETE_USERS_PERMISSION = 'delete_users'
NATIVE_LOGIN_ENABLED = p.toolkit.asbool(config.get('saml2.enable_native_login'))


def _take_from_saml_or_user(key, saml_info, data_dict):
    if key in saml_info:
        return saml_info[key][0]
    elif key in data_dict:
        return data_dict[key]
    else:
        raise KeyError('There are no [{}] neither in saml_info nor in data_dict'.format(key))


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@logic.auth_sysadmins_check
@logic.auth_allow_anonymous_access
def user_create(context, data_dict):
    """Deny user creation."""
    msg = p.toolkit._('Users cannot be created.')
    if NATIVE_LOGIN_ENABLED:
        return logic.auth.create.user_create(context, data_dict)
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
@logic.auth_allow_anonymous_access
def user_reset(context, data_dict):
    """Deny user reset."""
    msg = p.toolkit._('Users cannot reset passwords.')
    if NATIVE_LOGIN_ENABLED:
        return logic.auth.get.user_reset(context, data_dict)
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
@logic.auth_allow_anonymous_access
def request_reset(context, data_dict):
    """Deny user reset."""
    msg = p.toolkit._('Users cannot reset passwords.')
    method = p.toolkit.request.method
    username = p.toolkit.request.params.get('user', '')
    if NATIVE_LOGIN_ENABLED:
        user = model.User.get(username)
        if method == 'GET' or user is None or (
                method == 'POST' and is_local_user(user)):
            return logic.auth.get.request_reset(context, data_dict)
    return _no_permissions(context, msg)


def user_delete(context, data_dict):
    """Allow user deletion."""
    # import pprint
    user = context['auth_user_obj']
    msg = p.toolkit._('Users cannot remove users')
    return _no_permissions(context, msg)

rememberer_name = None


def delete_cookies():
    """Logout."""
    global rememberer_name
    if rememberer_name is None:
        plugins = p.toolkit.request.environ['repoze.who.plugins']
        saml_plugin = plugins.get('saml2auth')
        rememberer_name = saml_plugin.rememberer_name
    base.response.delete_cookie(rememberer_name)
    # We seem to end up with an extra cookie so kill this too
    domain = p.toolkit.request.environ['HTTP_HOST']
    base.response.delete_cookie(rememberer_name, domain='.' + domain)


def is_local_user(userobj):
    """
    Returns True if userobj is not a SAML2 user.

    """
    return True if saml2_get_user_info(userobj.id) is None else False


def assign_default_role(context, user_name):
    """Creates organization member roles according to saml2.default_org
    and saml2.default_role or does nothing if those are not set.

    """
    user_org = config.get('saml2.default_org')
    user_role = config.get('saml2.default_role')
    if user_org and user_role:
        member_dict = {
            'id': user_org,
            'username': user_name,
            'role': user_role
        }
        p.toolkit.get_action('organization_member_create')(
            context, member_dict)


def get_came_from(relay_state):
    """Returns the original URL requested by the user before
    authentication, parsed from the SAML2 RelayState
    """
    rs_parsed = urlparse.urlparse(relay_state)
    came_from = urlparse.parse_qs(rs_parsed.query).get('came_from', None)
    if came_from is None:
        # No came_from param was supplied to /user/login
        return None
    cf_parsed = urlparse.urlparse(came_from[0])
    # strip scheme and host to prevent redirection to other domains
    came_from = urlparse.urlunparse(('',
                                     '',
                                     cf_parsed.path,
                                     cf_parsed.params,
                                     cf_parsed.query,
                                     cf_parsed.fragment))
    log.debug('came_from = %s', came_from)
    return came_from.encode('utf8')


def saml2_get_userid_by_name_id(id):
    user_info = model.Session.query(SAML2User).\
        filter(SAML2User.name_id == id).first()
    return user_info.id if user_info is not None else user_info


def saml2_get_user_name_id(id):
    user_info = saml2_get_user_info(id)
    return user_info if user_info is None else user_info[0].name_id


def saml2_get_is_allow_update(id):
    saml2_set_context_variables_after_check_for_user_update(id)


def saml2_get_user_info(id):
    query = model.Session.query(SAML2User, model.User).\
        join(model.User, model.User.id == SAML2User.id).\
        filter(or_(func.lower(SAML2User.name_id) == func.lower(id),
                   SAML2User.id == id,
                   model.User.name == id)).first()
    return query


def saml2_user_delete(context, data_dict):
    if not data_dict.get('id') and data_dict.get('nameid'):
            saml2_user_id = saml2_get_userid_by_name_id(data_dict['nameid'])
            if saml2_user_id is not None:
                data_dict['id'] = saml2_user_id
            else:
                raise logic.NotFound('NameID "{id}" was not found.'.format(
                                            id=data_dict['nameid']))
    ckan_user_delete(context, data_dict)


def saml2_set_context_variables_after_check_for_user_update(id):
    c = p.toolkit.c
    c.allow_user_change = False
    user_info = saml2_get_user_info(id)
    if user_info is not None:
        c.allow_user_change = p.toolkit.asbool(
            config.get('ckan.saml2.allow_user_changes', False))
        c.is_allow_update = user_info[0].allow_update


def saml2_user_update(context, data_dict):
    if data_dict.get('password1', '') != '' or data_dict.get('password2', '') != '':
        raise logic.ValidationError({'password': [
            "This field cannot be modified."]})

    id = logic.get_or_bust(data_dict, 'id')
    name_id = saml2_get_user_name_id(id)
    if name_id is not None:
        c = p.toolkit.c
        saml2_set_context_variables_after_check_for_user_update(id)
        if c.allow_user_change:
            checkbox_checked = data_dict.get('checkbox_checked')
            allow_update_param = data_dict.get('allow_update')
            if checkbox_checked is not None:
                allow_update_param = p.toolkit.asbool(allow_update_param)
                model.Session.query(SAML2User).filter_by(name_id=name_id).\
                    update({'allow_update': allow_update_param})
                model.Session.commit()
                if not allow_update_param:
                    return {'name': data_dict['id']}
            else:
                if allow_update_param is not None:
                    allow_update_param = p.toolkit.asbool(allow_update_param)
                    model.Session.query(SAML2User).filter_by(name_id=name_id).\
                        update({'allow_update': allow_update_param})
                    model.Session.commit()
                    if not allow_update_param:
                        return {'name': data_dict['id']}
                else:
                    if not c.is_allow_update and context.get('ignore_auth'):
                        return ckan_user_update(context, data_dict)
                    return {'name': data_dict['id']}
            return ckan_user_update(context, data_dict)

        else:
            raise logic.ValidationError({'error': [
                "User accounts managed by Single Sign-On can't be modified"]})
    else:
        return ckan_user_update(context, data_dict)



class Saml2Plugin(p.SingletonPlugin):
    """SAML2 plugin."""

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthFunctions, inherit=True)
    p.implements(p.IConfigurer, inherit=True)
    p.implements(p.IConfigurable)
    p.implements(p.ITemplateHelpers)
    p.implements(p.IActions)

    def update_config(self, config):
        """Update environment config."""
        p.toolkit.add_resource('fanstatic', 'ckanext-saml2')
        p.toolkit.add_template_directory(config, 'templates')

    def make_mapping(self, key, config):
        """Map user data from .ini file."""
        data = config.get(key)
        mapping = {}
        for item in data.split():
            bits = item.split('~')
            mapping[bits[0]] = bits[1]
        return mapping

    def configure(self, config):
        """Apply mapping."""
        self.user_mapping = self.make_mapping('saml2.user_mapping', config)
        m = self.make_mapping('saml2.organization_mapping', config)
        self.organization_mapping = m

    def before_map(self, map):
        """Add few routes."""
        with SubMapper(
                map, controller='ckanext.saml2.plugin:Saml2Controller') as m:
            m.connect('saml2_unauthorized', '/saml2_unauthorized',
                      action='saml2_unauthorized')
            m.connect('saml2_slo', '/slo', action='slo')
            m.connect('staff_login', '/service/login', action='staff_login')

        return map

    def make_password(self):
        """Create a hard to guess password."""
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

    def identify(self):
        """
        Work around saml2 authorization.

        c.user contains the saml2 id of the logged in user we need to
        convert this to represent the ckan user.
        """
        # Can we find the user?
        c = p.toolkit.c
        environ = p.toolkit.request.environ

        name_id = environ.get('REMOTE_USER', '')
        log.debug("REMOTE_USER = \"{0}\"".format(name_id))

        name_id = unserialise_nameid(name_id).text
        if not name_id:
            log.info('Ignoring REMOTE_USER - does not look like a NameID')
            return
        log.debug('NameId: %s' % (name_id))

        saml2_user_info = saml2_get_user_info(name_id)
        log.debug("saml2_user_info = %r", saml2_user_info)
        
        if saml2_user_info is not None:
            c.user = saml2_user_info[1].name

        log.debug("identify(): c.user = %r", c.user)
        log.debug("repoze.who.identity = {0}".format(dict(environ["repoze.who.identity"])))

        # get the actual user info from the saml2auth client
        try:
            saml_info = environ["repoze.who.identity"]["user"]
            log.debug("identify(): saml_info = %r", saml_info)
            
        except KeyError:
            # This is a request in an existing session so no need to provision
            # an account, set c.userobj and return
            c.userobj = model.User.get(c.user)
            if c.userobj is not None:
                c.user = saml_info['maxemail'][0] # REMIND: this looks suspect

            log.debug("identify(): KeyError; saml_info = %r", saml_info)

            return

        try:
            # Update the user account from the authentication response
            # every time
            c.userobj = self._create_or_update_user(c.user, saml_info, name_id)
            c.user = c.userobj.name
        except Exception as e:
            log.exception(
                "Couldn't create or update user account ID:%s", c.user)
            c.user = None
            return

        # Update user's organization memberships either via the
        # configured saml2.org_converter function or the legacy GSA
        # conversion
        update_membership = False

        org_roles = {}
        # import the configured function for converting a SAML
        # attribute to a dict for create_organization()
        org_mapper_config = config.get('saml2.organization_mapper', None)
        get_org_roles = None
        if org_mapper_config is not None:
            try:
                module_name, function_name = org_mapper_config.split(':', 2)
                module = import_module(module_name)
                get_org_roles = getattr(module, function_name)
            except Exception as e:
                log.error("Couldn't import saml2.organization_mapper: %s", org_mapper_config)
                log.error("Error: %s", e)

        if get_org_roles is not None:
            update_membership = True
            org_roles = get_org_roles(saml_info)

        elif 'name' in self.organization_mapping and self.organization_mapping['name'] in saml_info:
            # Backwards compatibility for the original implementation
            # at
            # https://github.com/GSA/ckanext-saml2/blob/25521bdbb3728fe8b6532184b8b922d9fca4a0a0/ckanext/saml2/plugin.py
            org = {}
            # apply mapping
            self.update_data_dict(org, self.organization_mapping, saml_info)
            org_name = org['name']
            org_roles[org_name] = {
                'capacity': 'editor' if org['field_type_of_user'][0] == 'Publisher' else 'member',
                'data': org,
            }
            update_membership = True

        disable_organization_membership = config.get('saml2.disable_organization_membership', False)
        if disable_organization_membership:
            update_membership = False

        if update_membership:
            self.update_organization_membership(org_roles)

        # Redirect the user to the URL they requested before
        # authentication. Ideally this would happen in the controller
        # of the assertion consumer service but in lieu of one
        # existing this location seems reliable.
        request = p.toolkit.request
        if request.method == 'POST':
            relay_state = request.POST.get('RelayState', None)
            if relay_state:
                came_from = get_came_from(relay_state)
                if came_from:
                    h.redirect_to(h.url_for(came_from))

            # TODO CKAN identify user in all requests. Discover why this is here
            if '/login' in request.url:
                redirect_after_login = config.get('saml2.redirect_after_login', '/dashboard')
                h.redirect_to(redirect_after_login)

    def _create_or_update_user(self, user_name, saml_info, name_id):
        """Create or update the subject's user account and return the user
        object"""
        data_dict = {}
        user_schema = schema.default_update_user_schema()

        is_new_user = False
        userobj = model.User.get(user_name)
        if userobj is None:
            is_new_user = True
            user_schema = schema.default_user_schema()
        else:
            if userobj.is_deleted():
                # If account exists and is deleted, reactivate it. Assumes
                # only the IAM driving the IdP will deprovision user
                # accounts and wouldn't allow a user to authenticate for
                # this app if they shouldn't have access.
                log.debug("Reactivating user")
                userobj.activate()
                userobj.commit()

            data_dict = p.toolkit.get_action('user_show')(
                data_dict={'id': user_name, })

        # Merge SAML assertions into data_dict according to
        # user_mapping
        update_user = self.update_data_dict(data_dict,
                                            self.user_mapping,
                                            saml_info)

        # Remove validation of the values from id and name fields
        user_schema['id'] = [p.toolkit.get_validator('not_empty')]
        user_schema['name'] = [p.toolkit.get_validator('not_empty')]
        context = {'schema': user_schema, 'ignore_auth': True}
        if is_new_user:
            email = _take_from_saml_or_user('email', saml_info, data_dict)
            new_user_username = _get_random_username_from_email(email)

            name_id_from_saml2_NameID = config.get('saml2.name_id_from_saml2_NameID', False)
            if not name_id_from_saml2_NameID:
                name_id = _take_from_saml_or_user('id', saml_info, data_dict)
            data_dict['name'] = new_user_username
            data_dict['id'] = unicode(uuid.uuid4())
            log.debug("Creating user: %s", data_dict)
            data_dict['password'] = self.make_password()
            new_user = p.toolkit.get_action('user_create')(context, data_dict)
            assign_default_role(context, new_user_username)
            model.Session.add(SAML2User(id=new_user['id'],
                                        name_id=name_id))
            model.Session.commit()
            return model.User.get(new_user_username)
        elif update_user:
            c = p.toolkit.c
            saml2_set_context_variables_after_check_for_user_update(
                data_dict.get('id', None))
            if c.allow_user_change and not c.is_allow_update:
                log.debug("Updating user: %s", data_dict)
                p.toolkit.get_action('user_update')(context, data_dict)
        return model.User.get(user_name)

    def update_organization_membership(self, org_roles):
        """Create organization using mapping.

        org_roles is a dict whose keys are organization IDs, and
        values are a dict containing 'capacity' and 'data', e.g.,

        org_roles = {
            'org1': {
                'capacity': 'member',
                'data': {
                    'id': 'org1',
                    'description': 'A fun organization',
                    ...
                },
            },
            ...
        }

        """

        create_orgs = p.toolkit.asbool(
            config.get('saml2.create_missing_orgs', False))
        remove_user_from_orgs = p.toolkit.asbool(
            config.get('saml2.rvm_users_from_orgs', True))
        context = {'ignore_auth': True}
        site_user = p.toolkit.get_action('get_site_user')(context, {})
        c = p.toolkit.c

        # Create missing organisations
        if create_orgs:
            for org_id in org_roles.keys():
                org = model.Group.get(org_id)

                if not org:
                    context = {'user': site_user['name']}
                    data_dict = {
                        'id': org_id,
                    }
                    data_dict.update(org_roles[org_id].get('data', {}))
                    try:
                        p.toolkit.get_action('organization_create')(
                            context, data_dict)
                    except logic.ValidationError, e:
                        log.error("Couldn't create organization: %s", org_id)
                        log.error("Organization data was: %s", data_dict)
                        log.error("Error: %s", e)

        # Create or delete membership according to org_roles
        all_orgs = p.toolkit.get_action('organization_list')(context, {})
        for org_id in all_orgs:
            org = model.Group.get(org_id)

            # skip to next if the organisation doesn't exist
            if org is None:
                continue

            member_dict = {
                'id': org_id,
                'object': c.userobj.id,
                'object_type': 'user',
            }
            member_context = {
                'user': site_user['name'],
                'ignore_auth': True,
            }
            if org_id in org_roles:
                # add membership
                member_dict['capacity'] = org_roles[org_id]['capacity']
                p.toolkit.get_action('member_create')(
                    member_context, member_dict)
            else:
                if remove_user_from_orgs:
                    # delete membership
                    p.toolkit.get_action('member_delete')(
                        member_context, member_dict)

    def update_data_dict(self, data_dict, mapping, saml_info):
        """Updates data_dict with values from saml_info according to
        mapping. Returns the number of items changes."""
        count_modified = 0
        for field in mapping:
            value = saml_info.get(mapping[field])
            if value:
                # If list get first value
                if isinstance(value, list):
                    value = value[0]
                if not field.startswith('extras:'):
                    if data_dict.get(field) != value:
                        data_dict[field] = value
                        count_modified += 1
                else:
                    if 'extras' not in data_dict:
                        data_dict['extras'] = []
                    data_dict['extras'].append(
                        dict(key=field[7:], value=value))
                    count_modified += 1
        return count_modified

    def login(self):
        """
        Login definition.

        We can be here either because we are requesting a login (no user)
        or we have just been logged in.
        """

        if not p.toolkit.c.user:
            # A 401 HTTP Status will cause the login to be triggered
            return base.abort(401, p.toolkit._('Login required!'))
        h.redirect_to('/')

        c = p.toolkit.c
        if not c.user:
            try:
                if p.toolkit.request.environ['pylons.routes_dict']['action'] == 'staff_login':
                    return
            except Exception:
                pass
            if NATIVE_LOGIN_ENABLED:
                c.sso_button_text = config.get('saml2.login_form_sso_text')
                if p.toolkit.request.params.get('type') != 'sso':
                    came_from = p.toolkit.request.params.get('came_from', None)
                    if came_from:
                        c.came_from = came_from
                    return
            return base.abort(401)
        h.redirect_to(controller='user', action='dashboard')

    def logout(self):
        """Logout definition."""
        environ = p.toolkit.request.environ

        userobj = p.toolkit.c.userobj
        sp_initiates_slo = p.toolkit.asbool(config.get('saml2.sp_initiates_slo', True))
        if not sp_initiates_slo or userobj and is_local_user(userobj):
            plugins = environ['repoze.who.plugins']
            friendlyform_plugin = plugins.get('friendlyform')
            rememberer = environ['repoze.who.plugins'][friendlyform_plugin.rememberer_name]
            domain = p.toolkit.request.environ['HTTP_HOST']
            base.response.delete_cookie(rememberer.cookie_name, domain='.' + domain)
            base.response.delete_cookie(rememberer.cookie_name)
            h.redirect_to(controller='home', action='index')

        subject_id = environ["repoze.who.identity"]['repoze.who.userid']
        name_id = unserialise_nameid(subject_id)
        client = environ['repoze.who.plugins']["saml2auth"]
        rem = environ['repoze.who.plugins'][client.rememberer_name]
        rem.forget(environ, subject_id)
        # MAX does not support slo, let us fake one.
        return h.redirect_to('/slo?SAMLResponse=1')

    def abort(self, status_code, detail, headers, comment):
        """
        HTTP Status 401 causes a login redirect.

        We need to prevent this unless we are actually trying to login.
        """
        if (status_code == 401 and
           p.toolkit.request.environ['PATH_INFO'] != '/user/login'):
                if not p.toolkit.c.user:
                    if NATIVE_LOGIN_ENABLED:
                        h.flash_error(_('Requires authentication'))
                    h.redirect_to('login', came_from=h.full_current_url())
                h.redirect_to('saml2_unauthorized')
        return (status_code, detail, headers, comment)

    def get_auth_functions(self):
        """We need to prevent some actions being authorized."""
        return {
            'user_create': user_create,
            'user_reset': user_reset,
            'user_delete': user_delete,
            'request_reset': request_reset,
        }

    def get_helpers(self):
        return {
            'saml2_get_user_name_id': saml2_get_user_name_id,
            'saml2_get_is_allow_update': saml2_get_is_allow_update
        }

    def get_actions(self):
        return {
            'user_delete': saml2_user_delete,
            'user_update': saml2_user_update
        }


class Saml2Controller(UserController):
    """SAML2 Controller."""

    _get_repoze_handler = UserController._get_repoze_handler

    def saml2_unauthorized(self):
        """Our you are not authorized page."""
        c = p.toolkit.c
        c.code = 401
        c.content = p.toolkit._('You are not authorized to do this')
        return p.toolkit.render('error_document_template.html')

    def slo(self):
        """SAML magic."""
        environ = p.toolkit.request.environ
        # so here I might get either a LogoutResponse or a LogoutRequest
        if 'QUERY_STRING' in environ:
            saml_resp = p.toolkit.request.GET.get('SAMLResponse', '')
            saml_req = p.toolkit.request.GET.get('SAMLRequest', '')

            if saml_req:
                log.debug('Received SLO request from IdP')
                # pysaml2 takes care of everything here via its
                # repoze.who plugin
            elif saml_resp:
             #   # fix the cert so that it is on multiple lines
             #   out = []
             #   # if on multiple lines make it a single one
             #   line = ''.join(saml_resp.split('\n'))
             #   while len(line) > 64:
             #       out.append(line[:64])
             #       line = line[64:]
             #   out.append(line)
             #   saml_resp = '\n'.join(out)
             #   try:
             #       res = client.saml_client.logout_request_response(
             #           saml_resp,
             #           binding=BINDING_HTTP_REDIRECT
             #       )
             #   except KeyError:
             #       # return error reply
             #       pass

                delete_cookies()
                return h.redirect_to(controller='user', action='logged_out')

    def staff_login(self):
        """Default login page for staff members."""
        return self.login()
