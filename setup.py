from setuptools import setup, find_packages

version = '0.1'

setup(
	name='ckanext-saml2',
	version=version,
	description="Saml2 authentication extension",
	long_description="""\
	""",
	classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
	keywords='',
	author='Toby Dacre',
	author_email='ckan@okfn.org',
	url='ckan.org',
	license='MIT',
	packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
	namespace_packages=['ckanext', 'ckanext.saml2'],
	include_package_data=True,
	zip_safe=False,
	install_requires=[
		# -*- Extra requirements: -*-
        'inotify_simple'
        'repoze.who==1.0.18',
        'python-memcached==1.48',
	],
	entry_points=\
	"""
        [ckan.plugins]
	# Add plugins here, eg
	saml2=ckanext.saml2.plugin:Saml2Plugin
	""",
)
