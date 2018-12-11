ckanext-saml2
==============
An extension to enable Single Sign On(SSO) for CKAN data portals via SAML2 Authentication.

#### Requirements
The following packages are required: memcached, repoze, m2crypto, xmlsec1, xmlsec1-openssl, swig

#### Installation
- To install this extension run the following commands (switch to python env first): then `pip install -r requirements.txt` & `python setup.py develop`
- Create custom database table:

```
paster saml2 create -c config_file
```
- Append `saml2` to the `ckan.plugins` list in your ckan configuration file (i.e: `/etc/ckan/production.ini`)
- make sure that fields are mapped correctly in `production.ini` i.e:
```
# saml2 config
saml2.user_mapping =
    email~mail
    fullname~field_display_name
    id~uid
    name~name

```

- There are two ways to map organisational SAML attributes:
```
# 1. A custom function that take a single argument `saml_info`, dict
# containing the SAML attributes. and returns a dict like the example
# below. This is useful when users may have roles in multiple
# organisations. Default: not set (None)
#
# {
#     'org1': {
#         'capacity': 'member',
#         'data': {
#             'id': 'org1',
#             'description': 'A fun organization',
#             ...
#          },
#     },
#     ...
# }

saml2.organization_mapper = ckanext.myckan.plugin:mapping_function


# 2. Specify a simple mapping from individual SAML attributes to
# organisation schema fields. Note: `saml2.organization_mapping` must
# be defined, with no value if it should not be used

saml2.organization_mapping =
    name~field_unique_id
    title~field_organization
    field_type_of_user~field_role
    extras:organization_type~field_organization_type
```

- By default, the SP doesn't create organisations specified in the SAML attributes but this can be configured:
```
# create organisations specified in SAML attributes that don't exist in CKAN? Default: False
saml2.create_missing_orgs = True
```

- The SP initiates SLO on CKAN logout by default. In order to make this more prominent you can add the directive `saml2.sp_initiates_slo` in ckan configuration file. Values `true`, `yes`, `on`, `y`, `t`, `1` are treated as true. To disable SP-initiated SLO and only logout from CKAN, set this directive to `false`, `no`, `off`, `n`, `f`, or `0`.
```
saml2.sp_initiates_slo = true
```

- Modify `ckanext/saml2/config/sp_config.py` to suit your needs. The BASE variable at the top need reference  the domain of the service provider (i.e changed to http://catalog.data.gov or wherever CKAN is currently hosted).
- Place your identity provider's `idp.xml` metadata here: `ckanext/saml2/config/`
- The certificates need to be placed in this directory: `ckanext/saml2/config/pki` (they need to be named
`mycert.pem` & `mykey.pem`)
- Generate the sp metadata (sp.xml):
`/usr/lib/ckan/bin/python /usr/lib/ckan/src/pysaml2/tools/make_metadata.py /usr/lib/ckan/src/ckanext-saml2/ckanext/saml2/config/sp_config.py > sp.xml` (the paths to `python`, `make_metadata.py` `sp_config.py` might vary depending on where you installed ckan in your virtual env)
- copy `ckanext/saml2/config/who.ini` to your ckan's config folder i.e: `/etc/ckan/who.ini`
- make sure that your webserver can write to `/var/www/sp.log`
- Add `saml2.default_org` and `saml2.default_role` - that values will be assigned to newly created users as organization and role in this organization accordingly
- In order to enable native login and registration as default option, add `saml2.enable_native_login = true|false` directive to config file.
- `saml2.login_form_sso_text = BUTTON_TEXT` allows you to controll label of SSO button at login page(default: 'Login with SSO').

#### Production deployment

To keep IdP metadata from `metadata_url` and stored at `local_path`
up-to-date automatically run the following script:
```
/usr/lib/ckan/default/bin/python ckanext/saml2/admin/fresh_idp_metadata.py -url metadata_url -path local_path
```
CKAN must be reloaded after the metadata is updated, by, for example, reloading httpd.


#### Command line

Create custom database table:
```
paster saml2 create -c config_file
```

Drop custom database tables::
```
paster saml2 drop -c config_file
```

#### API Changes

Users can also be deleted by Name ID by passing the `nameid` parameter:

    api/3/action/user_delete
    Parameters (id or nameid):
        - id (string) – the id, name of the user to delete
        - nameid (string) – SAML NameID of the user to delete

Update user via API. We can pass allow_update as parameter for allow or reject user custom profile data set:

    api/3/action/user_update
    Parameters (default parametrs and allow_update optional):
        - allow_update (True or False) – checked or unchecked checkbox for SSO user profile page

#### Known Issues

- The only binding supported for sending logout reponses for an IdP-initiated global logout is HTTP Redirect. As of v4.4.0 pysaml2's behaviour is to use a Post binding if the SP receives a logout request via either a Post or Redirect binding but it subsequently raises an exception. A workaround is modify the local copy of the IdP metadata by removing the element that declares support for the Post binding for logout, e.g., `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ... />`, which will cause pysaml2 to revert to a Redirect binding.

The included metadata update script performs this configuration update automatically.
