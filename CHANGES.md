# ckanext-saml2 change log

## 0.3.0

* Added a script ckanext/saml2/admin/fresh_idp_metadata.py to keep IdP
  metadata up-to-date

### Deprecations and Breaking Changes

* NameIDs are now stored in the saml2_user table, instead of as the
  user's username. No update method for existing data is provided.
* Deprecated the `saml2.local_email_domains` and
  `saml2.sso_email_domains` configuration directives in favour of a
  direct check for a NameID in the saml2_user table.


## 0.2.0

**Note**: This release requires the use of pysaml2's challenge_decider to enable single logout, which was not required in 0.1. See the sample who.ini configuration.

**Note**: If ckanext-saml was used to modify user privileges for user provisioning by the IdP, you now need to use [ckanext-acl](https://github.com/DataShades/ckanext-acl)

* Move responsibility for sending LogoutResponses from the plugin to pysaml2
* Removed user account permission admin to [ckanext-acl|https://github.com/DataShades/ckanext-acl]