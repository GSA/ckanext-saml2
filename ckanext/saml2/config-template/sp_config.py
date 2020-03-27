import os.path

from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI

BASE= 'https://catalog.data.gov/'
#BASE= 'https://saml-test.datagov.ckan.org/'
#BASE = 'http://localhost:5000/'
CONFIG_PATH = os.path.dirname(__file__)

CONFIG = {
    'entityid' : 'urn:mace:umu.se:saml:ckan:sp',
    'description': 'CKAN saml2 authorizor',
    'service': {
        'sp': {
            'name' : 'CKAN SP',
            'endpoints': {
                'assertion_consumer_service': [BASE],
                'single_logout_service' : [(BASE + 'slo',
                                            BINDING_HTTP_REDIRECT)],
            },
            'required_attributes': [
                'uid',
                'name',
                'mail',
                'status',
                'roles',
                'field_display_name',
                'realname',
                'field_unique_id',
                'field_type_of_user',
                'field_organization_type',
                'field_agency',
                'field_organization',
            ],
            'allow_unsolicited': True,
            'optional_attributes': [],
            'idp': ['urn:mace:umu.se:saml:ckan:idp'],
        }
    },
    'debug': 0,
    'key_file': CONFIG_PATH + '/pki/mykey.pem',
    'cert_file': CONFIG_PATH + '/pki/mycert.pem',
    'attribute_map_dir': CONFIG_PATH + '/../attributemaps',
    'metadata': {
       'local': [CONFIG_PATH + '/idp.xml'],
    },
    # -- below used by make_metadata --
    'organization': {
        'name': 'Exempel AB',
        'display_name': [('Exempel AB','se'),('Example Co.','en')],
        'url':'http://www.example.com/ckan',
    },
    'contact_person': [{
        'given_name':'John',
        'sur_name': 'Smith',
        'email_address': ['john.smith@example.com'],
        'contact_type': 'technical',
        },
    ],
    'name_form': NAME_FORMAT_URI,
    'logger': {
        'rotating': {
            'filename': '/tmp/sp.log',
            'maxBytes': 100000,
            'backupCount': 5,
            },
        'loglevel': 'error',
    }
}
