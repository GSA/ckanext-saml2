#! /usr/bin/env python

import xml.etree.cElementTree as ET
from datetime import datetime
import requests
from argparse import ArgumentParser


parser = ArgumentParser()

parser.add_argument(
    '-url',
    help='URL for metadata download'
)
parser.add_argument(
    '-path',
    help='Path to current metadata xml file'
)

args = parser.parse_args()

tree = ET.ElementTree(file=args.path)
root = tree.getroot().attrib
validUntil = root['validUntil']
datetime_object = datetime.strptime(validUntil, '%Y-%m-%dT%H:%M:%SZ')
validUntil = datetime_object.date()
leftDays = (validUntil - datetime.today().date()).days

if leftDays <= 1:
    try:
        r = requests.get(args.url, stream=True, verify=False)
    except requests.exceptions.RequestException as e:
        print 'Error: {0}'.format(e)
    if r.status_code == 200:
        with open('nswidhub-test-idp-new.xml', 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
