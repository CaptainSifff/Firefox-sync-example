#!/usr/bin/env python
## Demonstrates certain parts of accessing (and decoding/decrypting)
## data stored by Firefox Sync ("Weave") from Python
##
##
## (c) 2011 Ivo van der Wijk, m3r consultancy, Christian Geier
## See LICENSE for licensing details
import requests  # easy_install this
import json
import base64
import hashlib
import hmac
from M2Crypto.EVP import Cipher
import time
import pprint


class SyncSample(object):
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
        r = requests.get(url, auth=(self.username, self._password))
        #print "Url:", url, "Node:", r.content, "[S:", r.status_code, "]"
        return r.content

    def get(self, path):
        url = '/'.join((self.node, self.api, self.username, path))
        r = requests.get(url, auth=(self.username, self._password))
        return json.loads(r.content)

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
        hmac = payload['hmac'].decode("base64")
        default = self.cipher_decrypt(ciphertext, self.encryption_key, IV)['default']
        self.privkey = default[0].decode("base64")
        self.privhmac = default[1].decode("base64")

    def decrypt(self, data):
        ciphertext = data['ciphertext'].decode("base64")
        IV = data['IV'].decode("base64")
        hmac = data['hmac'].decode("base64")

        return self.cipher_decrypt(ciphertext, self.privkey, IV)

    def history(self, time=None):
        if time == None:
            d = self.get("storage/history")
        else:
            d = self.get("storage/history?newer=%s" % time)
        return d

    def passwords(self):
        d = self.get("storage/passwords?full=1")
        res = []
        for p in d:
            payload = json.loads(p['payload'])
            res.append(self.decrypt(payload))
        return res

    def hist_item(self, id):
        d = self.get("storage/history/%s" % id)
        payload = json.loads(d['payload'])
        return self.decrypt(payload)

    @staticmethod
    def encode_username(u):
        if '@' in u:
            return base64.b32encode(hashlib.sha1(u).digest()).lower()
        else:
            return u

    @staticmethod
    def hmac_sha256(key, s):
        return hmac.new(key, s, hashlib.sha256).digest()

    @staticmethod
    def decode_passphrase(p):
        def denormalize(k):
            """ transform x-xxxxx-xxxxx etc into something b32-decodable """
            tmp = k.replace('-', '').replace('8', 'l').replace('9', 'o').upper()
            padding = (8 - len(tmp) % 8) % 8
            return tmp + '=' * padding
        return base64.b32decode(denormalize(p))

if __name__ == '__main__':
    configfile = "~/.firefoxsyncrc"
    from ConfigParser import SafeConfigParser
    import ConfigParser
    from os import path
    import argparse
    configfile = path.expanduser(configfile)
    parser = SafeConfigParser()
    parser.read(configfile)
    username = parser.get('server_settings', 'username')
    password = parser.get('server_settings', 'password')
    passphrase = parser.get('server_settings', 'passphrase')
    try:
        server = parser.get('server_settings', 'server')
    except  ConfigParser.NoOptionError:
        server = "https://auth.services.mozilla.com"

    parser = argparse.ArgumentParser(
            description="prints urls stored in FirefoxSync (Weave)")
    parser.add_argument("-t", "--time", action="store", dest="time",
                help="print all URLs since this (POSIX) time (as POSIX)")
    args = parser.parse_args()
    since_time = args.time
    syncer = SyncSample(username, password, passphrase, server=server)
    meta = syncer.get_meta()
    assert meta['storageVersion'] == 5

    ids = syncer.history(since_time)
    for one_id in ids:
        print syncer.hist_item(one_id)[u'histUri']
