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
    jws_repr = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

    key = ''.join([chr(i) for i in [3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163]])

    def test_sha256(self):
        j = jws.JwsHmacSha()
        self.assertEqual(j.decode(self.jws_repr, self.key),
                         { 'headers': {u'alg': u'HS256', u'typ': u'JWT'},
                           'payload': self.payload,
                           'valid': True })

        # this implementation encodes headers to JSON in a slightly different
        # way than the RFC, so to test the example, we'll just use the
        # raw header string.
        headers_str = '{"typ":"JWT",\r\n "alg":"HS256"}'
        self.assertEqual(j.encode_strings(headers_str, self.payload, self.key),
                         self.jws_repr)
        
        # test encoding and decoding using key id
        j = jws.JwsHmacSha(keydict={'secret': self.key, 'secret2': 'abcd'})
        self.assertEqual(j.decode(j.encode(self.payload, 'JWT',
                                           key_id='secret')),
                         { 'headers': {u'alg': u'HS256', u'typ': u'JWT',
                                       u'kid': u'secret'},
                           'payload': self.payload,
                           'valid': True })

        # test some errors
        with self.assertRaises(jws.KeyRequiredException):
            j.encode(self.payload)
        with self.assertRaises(jws.KeyNotFoundException):
            j.encode(self.payload, key_id='notfound')

        msg = j.encode(self.payload, key=self.key)
        with self.assertRaises(jws.KeyRequiredException):
            j.decode(msg)
        
        msg = j.encode(self.payload, key=self.key, key_id='secret')
        with self.assertRaises(jws.KeyNotFoundException): 
            jws.JwsHmacSha(keydict={'wrongkid': self.key}).decode(msg)
       

if __name__ == '__main__':
    unittest.main()
