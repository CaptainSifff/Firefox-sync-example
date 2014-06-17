#!/usr/bin/env python
"""
## Demonstrates certain parts of accessing (and decoding/decrypting)
## data stored by Firefox Sync ("Weave") from Python
##
##
## (c) 2011-2012 Ivo van der Wijk, m3r consultancy, Christian Geier
## See LICENSE for licensing details
"""
from __future__ import print_function
import requests  # easy_install this
import json
import base64
import hashlib
import hmac
from M2Crypto.EVP import Cipher


class SyncSample(object):
    """used for syncing with mozilla's sync service"""
    api = "1.1"
    HMAC_INPUT = "Sync-AES_256_CBC-HMAC256"

    def __init__(self, username, password, passphrase,
                 server="https://auth.services.mozilla.com"):
        self.username = self.encode_username(username)
        self._password = password
        self.server = server
        self.passphrase = self.decode_passphrase(passphrase)
        self.node = self.get_node().rstrip('/')
        self.encryption_key = self.hmac_sha256(self.passphrase, "%s%s\x01" % (self.HMAC_INPUT, self.username))
        self.get_key()

    def get_node(self):
        url = self.server + '/user/1.0/' + self.username + '/node/weave'
        req = requests.get(url, auth=(self.username, self._password))
        #print "Url:", url, "Node:", r.content, "[S:", r.status_code, "]"
        return req.content

    def get(self, path):
        url = '/'.join((self.node, self.api, self.username, path))
        req = requests.get(url, auth=(self.username, self._password))
        return json.loads(req.content)

    def _delete(self, path):
        url = '/'.join((self.node, self.api, self.username, path))
        req = requests.delete(url, auth=(self.username, self._password))
        return json.loads(req.content)

    def get_meta(self):
        data = self.get('storage/meta/global')
        payload = json.loads(data['payload'])
        return payload

    def cipher_decrypt(self, ciphertext, key, IV):
        cipher = Cipher(alg='aes_256_cbc', key=key, iv=IV, op=0)
        v = cipher.update(ciphertext)
        v = v + cipher.final()
        del cipher
        return json.loads(v)

    def get_key(self):
        data = self.get("storage/crypto/keys")
        payload = json.loads(data['payload'])
        ciphertext = payload['ciphertext'].decode("base64")
        IV = payload['IV'].decode("base64")
        #hmac = payload['hmac'].decode("base64")
        default = self.cipher_decrypt(ciphertext, self.encryption_key, IV)['default']
        self.privkey = default[0].decode("base64")
        self.privhmac = default[1].decode("base64")

    def decrypt(self, data):
        ciphertext = data['ciphertext'].decode("base64")
        IV = data['IV'].decode("base64")
        #hmac = data['hmac'].decode("base64")
        return self.cipher_decrypt(ciphertext, self.privkey, IV)

    def history(self, time=None):
        if time == None:
            d = self.get("storage/history")
        else:
            d = self.get("storage/history?newer=%s" % time)
        return d

    def passwords(self):
        data = self.get("storage/passwords?full=1")
        res = []
        for line in data:
            payload = json.loads(line['payload'])
            res.append(self.decrypt(payload))
        return res

    def hist_item(self, hist_id):
        data = self.get("storage/history/%s" % hist_id)
        payload = json.loads(data['payload'])
        return self.decrypt(payload)

    def delete_tabs(self):
        """delete saved tabs"""
        tabs = self.get('storage/tabs?full=1')
        tablist = list()
        for one in tabs:
            tablist.append(self.decrypt(json.loads(one['payload'])))
        for ind, one in enumerate(tablist):
            print(ind, ')', one['clientName'], '(', one['id'], ')')
        tdelete = int(raw_input('Which tab do You want to delete? '))
        print('deleting "', tablist[tdelete]['clientName'], '"')
        self._delete('storage/tabs/' + tablist[tdelete]['id'])

    @staticmethod
    def encode_username(uname):
        if '@' in uname:
            return base64.b32encode(hashlib.sha1(uname.lower()).digest()).lower()
        else:
            return uname

    @staticmethod
    def hmac_sha256(key, string):
        return hmac.new(key, string, hashlib.sha256).digest()

    @staticmethod
    def decode_passphrase(passphrase):
        def denormalize(k):
            """ transform x-xxxxx-xxxxx etc into something b32-decodable """
            tmp = k.replace('-', '').replace('8', 'l').replace('9', 'o').upper()
            padding = (8 - len(tmp) % 8) % 8
            return tmp + '=' * padding
        return base64.b32decode(denormalize(passphrase))


def main():
    configfile = "~/.firefoxsyncrc"
    import ConfigParser
    import argparse
    import getpass
    import time
    import sys
    from os import path
    from ConfigParser import SafeConfigParser

    configfile = path.expanduser(configfile)
    parser = SafeConfigParser()
    parser.read(configfile)
    try:
        username = parser.get('server_settings', 'username')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        username = raw_input('Username: ')
    try:
        password = parser.get('server_settings', 'password')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        password = getpass.getpass('Password (for the server): ')
    try:
        passphrase = parser.get('server_settings', 'passphrase')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        passphrase = getpass.getpass('Passphrase (for decryption): ')
    try:
        server = parser.get('server_settings', 'server')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        server = "https://auth.services.mozilla.com"

    parser = argparse.ArgumentParser(
            description="prints urls stored in FirefoxSync (Weave)")
    parser.add_argument("-t", "--time", action="store", dest="time",
                help="print all URLs since this (POSIX) time (as POSIX)")
    parser.add_argument('-d', action='store_true', dest='daemon_mode',
            default=False, help='keep running and check for new history items \
            every ten minutes')
    parser.add_argument('-n', action='store_true', dest='now',
            default=False, help='print history from now (only makes sense \
                    with -d')
    parser.add_argument('--delete-tabs', action='store_true', dest='dtabs',
            default=False, help='presents user with list of computers with \
                    synced tabs, ask user which to delete and deletes it')
    args = parser.parse_args()

    syncer = SyncSample(username, password, passphrase, server=server)
    meta = syncer.get_meta()
    assert meta['storageVersion'] == 5

    since_time = args.time
    if args.now:
        since_time = time.time()

    sleeptime = 600
    if args.dtabs:
        syncer.delete_tabs()
        sys.exit()
    elif args.daemon_mode:
        while 1:
            last_time = time.time()
            ids = syncer.history(since_time)
            for one_id in ids:
                print(syncer.hist_item(one_id)[u'histUri'])
            del syncer
            time.sleep(sleeptime)
            since_time = last_time
    else:
        ids = syncer.history(since_time)
        for one_id in ids:
            print(syncer.hist_item(one_id)[u'histUri'])


if __name__ == '__main__':
    main()
