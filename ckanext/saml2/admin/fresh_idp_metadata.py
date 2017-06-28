#! /usr/bin/env python

import sys
import os
import xml.etree.cElementTree as ET
from datetime import datetime
from argparse import ArgumentParser
import requests

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "dsig": "http://www.w3.org/2000/09/xmldsig#",
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "mdattr": "urn:oasis:names:tc:SAML:metadata:attribute",
    "mdext": "urn:oasis:names:tc:SAML:metadata:extension",
    "ns10": "urn:oasis:names:tc:SAML:profiles:v1metadata",
    "query": "urn:oasis:names:tc:SAML:metadata:ext:query",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "x500": "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance"
}

parser = ArgumentParser()

parser.add_argument(
    'metadata_url',
    help='URL for metadata download'
)
parser.add_argument(
    'local_path',
    help='Path to current metadata xml file'
)

parser.add_argument(
    '-k',
    '--insecure',
    help='Don\'t verify metadata security certificate',
    action='store_true'
)

args = parser.parse_args()

tree = ET.ElementTree(file=args.local_path)
root = tree.getroot().attrib
valid_until = root.get('validUntil', None)
if not valid_until:
    sys.exit('Metadata has no expiry date')

del root
del tree

valid_until = datetime.strptime(valid_until, '%Y-%m-%dT%H:%M:%SZ').date()
days_till_expiry = (valid_until - datetime.utcnow().date()).days

#print '%s days till expiry' % (days_till_expiry)

if days_till_expiry <= 4:
    try:
        r = requests.get(args.metadata_url,
                         allow_redirects=True,
                         verify=(not args.insecure))
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print 'Error: {0}'.format(e)
        sys.exit('Error downloading new metadata XML')

    try:
        metadata = ET.ElementTree(ET.fromstring(r.text))
    except ET.ParseError as e:
        print 'ParseError: {0}'.format(e)
        sys.exit('Error parsing new metadata XML')

    # Remove IdP config for POST binding for SLO, which ckanext-saml2
    # currently doesn't support, forcing pysaml2 to use the Redirect
    # binding
    for idpsso in metadata.findall('./md:IDPSSODescriptor', NS):
        for element in idpsso.findall('./md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]', NS):
            #print ET.tostring(element)
            idpsso.remove(element)
            #print "Removed IdP POST binding SLO config"

    # Write to temp file
    tmp_filename = 'idp-metadata-{0}.xml'.format(datetime.now().strftime('%Y-%m-%dT%H%M%S'))
    tmp_path = os.path.join(os.path.dirname(args.local_path), tmp_filename)
    metadata.write(tmp_path, encoding="utf-8")

    # Atomically replace old with new
    os.rename(tmp_path, args.local_path)
    #print "Replaced metadata"
