from ckan.lib.cli import CkanCommand
import paste.script
import logging
import ckanext.saml2.saml2_model.base as base_model

log = logging.getLogger('ckanext.anzlic')


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
        """Command itself."""
        self._load_config()

        if not len(self.args):
            print self.usage
        elif self.args[0] == 'init':
            self._init()
        elif self.args[0] == 'drop':
            self._drop()
        elif self.args[0] == 'create':
            self._create()

    def _init(self):
        self._drop()
        self._create()
        log.info("DB tables are reinitialized")

    def _drop(self):
        base_model.drop_tables()
        log.info("DB tables are removed")

    def _create(self):
        base_model.create_tables()
        log.info("DB tables are setup")
