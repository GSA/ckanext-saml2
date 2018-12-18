import os.path

from pylons import config

from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI

base = config.get('saml2.site_url', None)
config_path = config.get('saml2.config_path', None)
idp_url = config.get('saml2.idp_url', None)

CONFIG = {
    'entityid' : base,
    'description': 'CKAN saml2 authorizor',
    'service': {
        'sp': {
            'name' : 'CKAN SP',
            'endpoints': {
                'assertion_consumer_service': [base],
                'single_logout_service' : [(base + 'slo',
                                            BINDING_HTTP_REDIRECT)],
            },
            'allow_unsolicited': True,
            'required_attributes': ['maxEmail'],
            'idp': [idp_url],
            'name_id_format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        }
    },
    'allow_unknown_attributes': True,
    'debug': 0,
    'key_file': config_path + '/pki/mykey.pem',
    'cert_file': config_path + '/pki/mycert.pem',
    'attribute_map_dir': config_path + '/attributemaps',
    'metadata': {
       'local': [config_path + '/idp.xml'],
    },
    # -- below used by make_metadata --
    'logger': {
        'rotating': {
            'filename': '/tmp/sp.log',
            'maxBytes': 100000,
            'backupCount': 5,
            },
        'loglevel': 'error',
    }
}
