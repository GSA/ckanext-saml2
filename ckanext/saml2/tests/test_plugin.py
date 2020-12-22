# encoding: utf-8

'''Tests for the ckanext.datagovcatalog extension.'''

from nose.tools import assert_true
import ckan.plugins as p

class TestPluginLoaded(object):
    '''Tests for the ckanext.datagovcatalog.plugin module.'''

    def test_plugin_loaded(self):
        assert_true(p.plugin_loaded('saml2'))