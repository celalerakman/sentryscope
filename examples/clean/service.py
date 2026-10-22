"""Constrained alternatives for selected unsafe patterns."""
import hashlib
import json
import secrets
import tempfile


def user_query(value,cursor):
    return cursor.execute('SELECT * FROM users WHERE name=?',(value,))


def calculate(value):
    data = json.loads(value)
    if not isinstance(data,dict) or data.get('operation')!='add':
        raise ValueError('Unsupported operation')
    left,right = data['left'],data['right']
    if type(left) is not int or type(right) is not int:
        raise ValueError('Integers required')
    return left+right


def issue_token():
    return secrets.token_urlsafe(32)


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def temporary_artifact():
    with tempfile.TemporaryFile() as stream:
        stream.write(b'example')
        stream.seek(0)
        return stream.read()
