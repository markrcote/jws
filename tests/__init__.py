# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import hashlib
import hmac
import jws
import unittest

class TestHmac(unittest.TestCase):

    payload = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'

    def otest_sha256_no_key(self):
        headers_b64 = base64.urlsafe_b64encode('{"alg":"HS256","typ":"JWT"}')
        payload_b64 = base64.urlsafe_b64encode(self.payload)
        signature_b64 = base64.urlsafe_b64encode(hashlib.sha256(
                headers_b64 + '.' + payload_b64).digest())
        jws_repr = headers_b64 + '.' + payload_b64 + '.' + signature_b64

        j = jws.JwsSha256()
        msg = j.encode(self.payload, 'JWT')
        self.assertEqual(msg, jws_repr)
        self.assertEqual(j.decode(jws_repr),
                         { 'headers': {u'alg': u'HS256', u'typ': u'JWT'},
                           'payload': self.payload,
                           'valid': True })

    def test_sha256_with_key(self):
        keys = {'mykeyid': 'myverysecretkey'}
        headers_b64 = base64.urlsafe_b64encode('{"alg":"HS256","typ":"JWT","kid":"mykeyid"}')
        payload_b64 = base64.urlsafe_b64encode(self.payload)
        digest = hmac.new('myverysecretkey', headers_b64 + '.' + payload_b64,
                          hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(digest)
        jws_repr = headers_b64 + '.' + payload_b64 + '.' + signature_b64

        j = jws.JwsSha256(keys)
        msg = j.encode(self.payload, 'JWT', 'mykeyid')
        self.assertEqual(msg, jws_repr)
        self.assertEqual(j.decode(jws_repr),
                         { 'headers': {u'alg': u'HS256', u'kid': 'mykeyid', u'typ': u'JWT'},
                           'payload': self.payload,
                           'valid': True })

        # use an incorrect key
        digest = hmac.new('thewrongkey', headers_b64 + '.' + payload_b64,
                          hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(digest)
        jws_repr = headers_b64 + '.' + payload_b64 + '.' + signature_b64

        self.assertEqual(j.decode(jws_repr),
                         { 'headers': {u'alg': u'HS256', u'kid': 'mykeyid', u'typ': u'JWT'},
                           'payload': self.payload,
                           'valid': False })

        # use missing key
        self.assertRaises(jws.KeyIdNotFoundException, j.encode, self.payload,
                          'JWT', 'missingkeyid')

        headers_b64 = base64.urlsafe_b64encode('{"alg":"HS256","typ":"JWT","kid":"missingkeyid"}')
        signature_b64 = base64.urlsafe_b64encode(digest)
        jws_repr = headers_b64 + '.' + payload_b64 + '.' + signature_b64
        self.assertRaises(jws.KeyIdNotFoundException, j.decode, jws_repr)

if __name__ == '__main__':
    unittest.main()
