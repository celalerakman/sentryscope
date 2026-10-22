"""Static-analysis input. These functions are intentionally unsafe and never run."""
import hashlib
import os
import pickle
import random
import subprocess
import tempfile


def user_query(value,cursor):
    query = 'SELECT * FROM users WHERE name=' + value
    return cursor.execute(query)


def launch(value):
    return subprocess.run(value,shell=True)


def calculate(value):
    return eval(value)


def restore(value):
    return pickle.loads(value)


def read_document(filename):
    return open(filename).read()


def issue_token():
    access_token = random.random()
    return access_token


def unsafe_defaults():
    digest = hashlib.md5(b'content')
    filename = tempfile.mktemp()
    os.chmod(filename,0o777)
    return filename,digest
