#! /usr/bin/env python

import sys
import os
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
    new_filename = '/tmp/' + os.path.basename(args.path)
    try:
        r = requests.get(args.url, stream=True, verify=False)
    except requests.exceptions.RequestException as e:
        print 'Error: {0}'.format(e)
        sys.exit('Error while try to download new metadata xml file')
    if r.status_code == 200:
        with open(new_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
    f = open(new_filename, 'r')
    data = f.read()
    f.close()
    try:
        x = ET.fromstring(data)
    except ET.ParseError as e:
        print 'ParseError: {0}'.format(e)
        sys.exit('Error with new metadata xml file')
