# ckanext-saml2 change log

## Next release

*

## 0.2.0

**Note**: This release requires the use of pysaml2's challenge_decider to enable single logout, which was not required in 0.1. See the sample who.ini configuration.

**Note**: If ckanext-saml was used to modify user privileges for user provisioning by the IdP, you now need to use [ckanext-acl](https://github.com/DataShades/ckanext-acl)

* Move responsibility for sending LogoutResponses from the plugin to pysaml2
* Removed user account permission admin to [ckanext-acl|https://github.com/DataShades/ckanext-acl]