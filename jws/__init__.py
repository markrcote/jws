# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.


# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

__all__ = ['JwsBase', 'JwsHmacSha', 'KeyRequiredException',
           'KeyNotFoundException']

import base64
import hashlib
import hmac

try:
    import json
except ImportError:
    import simplejson as json


class KeyRequiredException(Exception):
    def __init__(self):
        Exception.__init__(self, 'a key is required but was not provided')


class KeyNotFoundException(Exception):
    def __init__(self):
        Exception.__init__(self, 'a matching key was not found in the store')


class JwsBase(object):

    def __init__(self, algid):
        self.algid = algid

    def b64encode(self, data):
        return base64.urlsafe_b64encode(data).rstrip('=')

    def b64decode(self, data):
        quads = len(data) % 4
        if quads == 2:
            data += '=='
        elif quads == 3:
            data += '='
        return base64.urlsafe_b64decode(data)

    def encode(self, payload, key, typ=None, extra_headers=()):
        headers = {'alg': self.algid}
        if typ:
            headers['typ'] = typ
        headers.update(extra_headers)
        headers_json = json.dumps(headers, separators=(',', ':'))
        return self.encode_strings(headers_json, payload, key)

    def encode_strings(self, headers, payload, key):
        header_b64 = self.b64encode(headers)
        payload_b64 = self.b64encode(payload)
        signing_input = header_b64 + '.' + payload_b64
        signature_b64 = self.b64encode(self.sign(signing_input, key))
        return signing_input + '.' + signature_b64

    def decode(self, jws_repr, key=None):
        header_b64, dot, rest = jws_repr.partition('.')
        payload_b64, dot, signature_b64 = rest.partition('.')
        headers = json.loads(self.b64decode(header_b64))
        payload = self.b64decode(payload_b64)
        signature = self.b64decode(signature_b64)
        signing_input = header_b64 + '.' + payload_b64
        return {'headers': headers, 'payload': payload,
                'valid': self.validate(headers, signing_input, key,
                                       signature)}

    def validate(self, headers, signing_input, key, signature):
        return signature == self.sign(signing_input, key)

    def sign(self, signing_input, key):
        raise NotImplementedError


class JwsHmacSha(JwsBase):

    """Jws with HMAC SHA authentication.
    You can include a dict (or dict-like object supporting get()) of keys.
    In this case, you can provide a key id to encode(), mapping to a key in
    keydict, instead of directly passing the key.
    Similarly, if no key is passed to decode(), the function will check for
    a 'kid' header and use that to fetch the appropriate key from keydict.
    Exceptions are raised if no key is found.
    """

    def __init__(self, bits=256, keydict={}):
        JwsBase.__init__(self, 'HS%d' % bits)
        self.keydict = keydict
        self.digestmod = getattr(hashlib, 'sha%d' % bits)

    def encode(self, payload, typ=None, key=None, key_id=None):
        extra_headers = {}
        if key_id:
            extra_headers['kid'] = key_id
        if not key:
            key = self.get_key_from_dict(key_id)
        return JwsBase.encode(self, payload, key, typ, extra_headers)

    def get_key_from_dict(self, key_id):
        if not key_id or not self.keydict:
            raise KeyRequiredException()
        key = self.keydict.get(key_id, None)
        if not key:
            raise KeyNotFoundException()
        return key

    def sign(self, signing_input, key):
        if not key:
            raise KeyRequiredException()
        return hmac.new(key, signing_input, self.digestmod).digest()

    def validate(self, headers, signing_input, key, signature):
        if not key:
            key = self.get_key_from_dict(headers.get('kid', None))
        return JwsBase.validate(self, headers, signing_input, key, signature)
