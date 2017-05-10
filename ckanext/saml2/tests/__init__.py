import nose.tools as nt

from ckan.tests.legacy.pylons_controller import PylonsTestCase

SAML_INFO = [
    '',
    'ausgrid=editor',
    'ausgrid=editor|australian-bureau-of-statistics=admin'
]

PylonsTestCase()


class SimpleNSWTest(PylonsTestCase, FunctionalTestBase):

    
