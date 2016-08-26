import os

import pytest
from OpenSSL import crypto
from jwkest.jwk import rsa_load, RSAKey

from alservice.mail import Email
from alservice.service.wsgi import create_app


class WriteToFileEmailFake(Email):
    def __init__(self):
        self.token = None
        self.email_to = None

    def send_mail(self, token: str, email_to: str):
        with open("token", "w") as f:
            f.write(token)


@pytest.fixture(scope="session")
def cert_and_key(tmpdir_factory):
    tmpdir = str(tmpdir_factory.getbasetemp())
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    create_self_signed_cert(cert_path, key_path)
    return cert_path, key_path


def create_self_signed_cert(cert_path, key_path):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "A"
    cert.get_subject().L = "B"
    cert.get_subject().O = "C"
    cert.get_subject().OU = "ACME Inc."
    cert.get_subject().CN = "D"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha1")

    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


@pytest.fixture
def app_config(cert_and_key):
    config = dict(
        TESTING=True,
        DEBUG=True,
        JWT_PUB_KEY=[cert_and_key[0]],
        SECRET_KEY='fdgfds%€#&436gfjhköltfsdjglök34j5oö43ijtglkfdjgasdftglok432jtgerfd',
        MESSAGE_TEMPLATE=os.path.join(os.path.dirname(__file__), "message.txt"),
        MESSAGE_FROM="al.service@example.com",
        MESSAGE_SUBJECT="Account registration",
        SMTP_SERVER="mail.example.com",
        SALT="fg9024jk5rmfdsvp0upASDIOPUmfadsf0qw3",
        DATABASE_URL=None,
        PIN_CHECK="((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})",
        PIN_EMPTY=False
    )
    return config


@pytest.fixture
def signing_key(cert_and_key):
    return RSAKey(key=rsa_load(cert_and_key[1]), alg="RS256")


@pytest.fixture()
def clean_dir(tmpdir):
    os.chdir(str(tmpdir))


@pytest.fixture
def app(app_config, clean_dir):
    return create_app(app_config, WriteToFileEmailFake())
