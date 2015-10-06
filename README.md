ckanext-saml2
=============

SAML2 Athentication extension

#### Requirements:
The following packages are required: memcached, repoze, m2crypto, xmlsec1, xmlsec1-openssl, swig 

####Setup Instructions:
- To install this extension run the following commands (switch to python env first): then `pip install -r requirements.txt` & `python setup.py develop` 
- To enable the saml2 plugin added it to the `ckan.plugins` list in your ckan configuration file (i.e: `/etc/ckan/production.ini`)
- Modify `ckanext/saml2/config/sp_config.py` to suit your needs. The BASE variable at the top need reference  the domain of the service provider (i.e changed to http://catalog.data.gov or wherever CKAN is currently hosted).
- Place your identity provider's `idp.xml` metadata here: `ckanext/saml2/config/`
- The certificates need to be placed in this directory: `ckanext/saml2/config/pki` (they need to be named
`mycert.pem` & `mykey.pem`)
- Generate the sp metadata (sp.xml):
`/usr/lib/ckan/bin/python /usr/lib/ckan/src/pysaml2/tools/make_metadata.py /usr/lib/ckan/src/ckanext-saml2/ckanext/saml2/config/sp_config.py > sp.xml` (the paths to `python`, `make_metadata.py` `sp_config.py` might vary depending on where you installed ckan in your virtual env)
- make sure that fields are mapped correctly in `production.ini` i.e:
```
#saml2 mappings
saml2.user_mapping =
  email~mail
  fullname~field_display_name
saml2.organization_mapping =
name~field_unique_id
title~field_organization
extras:organization_type~field_organization_type
```
- copy `ckanext/saml2/config/who.ini` to your ckan's config folder i.e: `/etc/ckan/who.ini`
- make sure that your webserver can write to `/var/www/sp.log`
