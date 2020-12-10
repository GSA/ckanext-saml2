import os.path

try:
    from ckan.common import config
except ImportError:  # CKAN 2.3
    from pylons import config

from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAME_FORMAT_URI

base = config.get('saml2.site_url', None)
issuer = config.get('saml2.issuer', base)
config_path = config.get('saml2.config_path', None)
idp_url = config.get('saml2.idp_url', None)

CONFIG = {
    'entityid' : issuer,
    'description': 'CKAN saml2 authorizer',
    'service': {
        'sp': {
            'name' : 'CKAN SP',
            'endpoints': {
                'assertion_consumer_service': [base],
                'single_logout_service' : [(base + 'slo',
                                            BINDING_HTTP_REDIRECT)],
            },
            'allow_unsolicited': True,
            'optional_attributes': [],
            'idp': [idp_url],
            'want_response_signed': False,
            'want_assertions_signed': False,
            'want_assertions_or_response_signed': True
        }
    },
    'debug': 1,
    'key_file': config_path + '/pki/mykey.pem',
    'cert_file': config_path + '/pki/mycert.pem',
    'encryption_keypairs': [
        {
        'key_file': config_path + '/pki/mykey.pem',
        'cert_file': config_path + '/pki/mycert.pem',
        },
    ],
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
    },
    "logging": {
        "version": 1,
        "formatters": {
            "simple": {
                "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
            },
        },
        "handlers": {
          "stdout": {
              "class": "logging.StreamHandler",
              "stream": "ext://sys.stdout",
              "level": "DEBUG",
              "formatter": "simple",
          },
        },
        "loggers": {
            "saml2": {
                "level": "DEBUG"
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": [
                "stdout",
            ],
        },
    }
}
