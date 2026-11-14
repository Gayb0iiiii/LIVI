#!/usr/bin/env python3
"""Generate a private deployment manifest from reviewed local package artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from supervisor import read_file, validate_manifest


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--auth-source',type=Path,required=True)
    p.add_argument('--network-source',type=Path,required=True)
    p.add_argument('--bluetooth-source',type=Path,required=True)
    p.add_argument('--auth-destination',default='/home/cruiser/LIVI/ax520-current-boot-service')
    p.add_argument('--network-destination',required=True)
    p.add_argument('--bluetooth-destination',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv)
    def sha(path):return hashlib.sha256(read_file(path)).hexdigest()
    value={'version':1,'seconds':300,'auth_dir':a.auth_destination,
           'auth_hashes':{relative:sha(a.auth_source/relative) for relative in
                          ('service.py','vendor/adb_observer.py','vendor/endpoint.py','vendor/verifier.py')},
           'artifacts':{'network':{'path':a.network_destination,'sha256':sha(a.network_source)},
                        'bluetooth':{'path':a.bluetooth_destination,'sha256':sha(a.bluetooth_source)}}}
    validate_manifest(value)
    fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(value,out,indent=2,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())

if __name__=='__main__':main()
