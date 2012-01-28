jws is a Python module for generating and verifying [JSON Web Signatures][1],
a format for authenticated web data.

Usage is intended to hide as many details of JWS as possible from the user,
while allowing extension to future protocols.

Only HMAC SHA256/384/512 is currently supported.

Encoding
--------

encode() takes a payload along with a key and/or key id, and optionally a
data type descriptor.

The data type descriptor is an arbitrary string describing the payload data
type, recorded as the 'typ' header.

If a key is given, it is always used.  If a key id is also given, it is
merely recorded as the 'kid' header.

If a key is not given, the key id is used to look up the associated key from
the key dictionary provided to the Jws object's constructor.  An exception is
raised if no key id is given, or if the key dict is not present, or if the key
id is not found in the dict, an appropriate exception is raised.

encode() returns the standard base64-encoded JWS representation,
<headers>.<payload>.<signature>


Decoding
--------

decode() takes a JWS representation and, optionally, a key.

If a key is given, it is used to attempt to verify the signature.

If a key is not given, decode() looks for a 'kid' header and uses this key id
to find the key as stored in the key dict passed to the Jws object's
constructor.  An exception is raised if a 'kid' header is not found, if the
key dict is not found, or if the key id is not found in the key dict.

decode() returns a dict with the following entries:

- 'headers': a dict of the JWS headers
- 'payload': the payload
- 'valid': True if the calculated signature matches the provided signature;
  False otherwise.


Examples:

    >>> import jws
    >>> # 512-bit HMAC SHA authentication with key dictionary
    >>> j = jws.JwsHmacSha(bits=512, keydict={'key1': 'abcd', 'key2': '1234'})

    >>> # encode a string using a key from the keydict
    >>> msg = j.encode('microfilm obtained', key_id='key1')
    >>> msg
    'eyJhbGciOiJIUzUxMiIsImtpZCI6ImtleTEifQ.bWljcm9maWxtIG9idGFpbmVk.pP308vIQ
    Hkax5HNDg86J6KAh1Pd4RBJbKYnCdMlQFNVmT2qM4oyX1728cHpgz6w1gmlcxEXmpIEKIRcaM
    1V4Mg'
    
    >>> # decode the message using the key indicated in the JWS header
    >>> j.decode(msg)
    {'headers': {u'alg': u'HS512', u'kid': u'key1'}, 'valid': True, 'payload':
    'microfilm obtained'}

    >>> # decode directly with key, without a key dict
    >>> j2 = jws.JwsHmacSha(bits=512)
    >>> j2.decode(msg, key='abcd')
    {'headers': {u'alg': u'HS512', u'kid': u'key1'}, 'valid': True, 'payload':
    'microfilm obtained'}

    >>> # errors

    >>> # can't decode without either a key or a keydict
    >>> j2.decode(msg)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "jws/__init__.py", line 68, in decode
        signature)}
      File "jws/__init__.py", line 116, in validate
        key = self.get_key_from_dict(headers.get('kid', None))
      File "jws/__init__.py", line 103, in get_key_from_dict
        raise KeyRequiredException()
    jws.KeyRequiredException: a key is required but was not provided

    >>> # can't encode without either a key or a keydict
    >>> j2.encode('{"temp":28}')
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "jws/__init__.py", line 98, in encode
        key = self.get_key_from_dict(key_id)
      File "jws/__init__.py", line 103, in get_key_from_dict
        raise KeyRequiredException()
    jws.KeyRequiredException: a key is required but was not provided

    >>> # can encode with given key and set arbitrary key id
    >>> msg2 = j2.encode('{"temp":28}', key='7890', key_id='key3')
    >>> jws.JwsHmacSha(bits=512, keydict={'key3': '7890', 'key4': 'wxyz'}) \
    >>>     .decode(msg2)
    {'headers': {u'alg': u'HS512', u'kid': u'key3'}, 'valid': True, 'payload':
    '{"temp":28}'}

    >>> # can't decode a message if key not given and key id not found in dict
    >>> jws.JwsHmacSha(bits=512, keydict={'key5':'./*-'}).decode(msg2)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "jws/__init__.py", line 68, in decode
        signature)}
      File "jws/__init__.py", line 116, in validate
        key = self.get_key_from_dict(headers.get('kid', None))
      File "jws/__init__.py", line 106, in get_key_from_dict
        raise KeyNotFoundException()
    jws.KeyNotFoundException: a matching key was not found in the store

    >>> # same with encode()
    >>> jws.JwsHmacSha(bits=512, keydict={'key5':'./*-'}) \
    >>>       .encode('the cheque is in the mail', key_id='key6')
    Traceback (most recent call last):
      File "<stdin>", line 2, in <module>
      File "jws/__init__.py", line 98, in encode
        key = self.get_key_from_dict(key_id)
      File "jws/__init__.py", line 106, in get_key_from_dict
        raise KeyNotFoundException()
    jws.KeyNotFoundException: a matching key was not found in the store


[1]: http://tools.ietf.org/html/draft-jones-json-web-signature-04
