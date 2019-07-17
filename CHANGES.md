# ckanext-saml2 change log

## 0.4.0

* New config fields added:
	* `saml2.rvm_users_from_orgs` - used in order to prevent Users from being removed from the Organization that are not mentioned within the response from IdP.
	* `saml2.disable_organization_membership` - used to avoid membership creation process for the User that is log in.
	* `saml2.redirect_after_login` - used to change default redirect URL after User log in.
	* `saml2.name_id_from_saml2_NameID` - if specified as `true`, the `nameid` will be taken from straight from the IdP response instead of find `id` key within the `saml_info` and `data_dict` variables at stage of User creation process.
* Added support for CKAN 2.8

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