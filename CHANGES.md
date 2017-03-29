# ckanext-saml2 change log

## Next release

**Note**: This release requires the use of pysaml2's challenge_decider to enable single logout, which was not required in 0.1. See the sample who.ini configuration.

* Move responsibility for sending LogoutResponses from the plugin to pysaml2