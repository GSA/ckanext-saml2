from ckan.lib.cli import CkanCommand
import paste.script
import logging
from ckanext.saml2.model.saml2_user import setupdb, dropdb


log = logging.getLogger('ckanext.saml2')


class Saml2Command(CkanCommand):
    """
    ckanext-saml2 management commands.

    Usage::
        paster saml2 [command]
    """

    summary = __doc__.split('\n')[0]
    usage = __doc__

    parser = paste.script.command.Command.standard_parser(verbose=True)
    parser.add_option('-c', '--config', dest='config',
                      default='development.ini',
                      help='Config file to use.')

    def command(self):
        self._load_config()

        if not len(self.args):
            print self.usage
        elif self.args[0] == 'drop':
            self._drop()
        elif self.args[0] == 'create':
            self._create()

    def _drop(self):
        dropdb()
        log.debug("DB tables are removed")

    def _create(self):
        setupdb()
        log.debug("DB tables are setup")
