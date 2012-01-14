# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import hashlib
import hmac

try:
    import json
except ImportError:
    import simplejson as json


class KeyIdNotFoundException(Exception):
    pass


class JwsBase(object):

    alg = None

    def encode(self, payload, typ=None, extra_headers={}):
        headers = {'alg': self.alg}
        if typ:
            headers['typ'] = typ
        headers.update(extra_headers)
        headers_json = json.dumps(headers, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(headers_json)
        payload_b64 = base64.urlsafe_b64encode(payload)
        signing_input = header_b64 + '.' + payload_b64
        signature_b64 = base64.urlsafe_b64encode(self.sign(signing_input,
                                                           headers))
        return signing_input + '.' + signature_b64

    def decode(self, jws_repr):
        header_b64, dot, rest = jws_repr.partition('.')
        payload_b64, dot, signature_b64 = rest.partition('.')
        headers = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = base64.urlsafe_b64decode(payload_b64)
        signature = base64.urlsafe_b64decode(signature_b64)
        signing_input = header_b64 + '.' + payload_b64
        calc_signature = self.sign(signing_input, headers)
        valid = signature == calc_signature
        return {'headers': headers, 'payload': payload, 'valid': valid}

    def sign(self, signing_input, headers):
        raise NotImplementedError


class JwsHmacBase(JwsBase):

    def __init__(self, keys=None):
        self.keys = keys

    def encode(self, payload, typ=None, kid=None):
        extra_headers = {'kid': kid} if kid is not None else {}
        return JwsBase.encode(self, payload, typ, extra_headers)

    def sign(self, signing_input, headers):
        if 'kid' in headers:
            try:
                h = hmac.new(self.keys[headers['kid']], signing_input,
                             self.hashmod)
            except KeyError:
                raise KeyIdNotFoundException()
        else:
            h = self.hashmod(signing_input)
        return h.digest()


class JwsSha256(JwsHmacBase):

    alg = 'HS256'
    hashmod = hashlib.sha256


class JwsSha384(JwsHmacBase):

    alg = 'HS384'
    hashmod = hashlib.sha384


class JwsSha512(JwsHmacBase):

    alg = 'HS512'
    hashmod = hashlib.sha512
