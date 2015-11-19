from base64 import urlsafe_b64encode
from calendar import monthrange
from datetime import datetime, timedelta
from email.mime.text import MIMEText
import hashlib
import random
import smtplib
from time import mktime, gmtime
from uuid import uuid4
from jwkest import jws
from jwkest.jwt import JWT
from alservice.exception import ALserviceTokenError, ALserviceAuthenticationError


class Email(object):
    TOKEN_REPLACE = "<<token>>"
    EMAIL_VERIFY_URL_REPLACE = "<<email_verify_url>>"
    TOKEN_PARAM = "token"

    def __init__(self, subject, message, email_from, smtp_server, verify_url):
        self.subject = subject
        self.message = message
        self.email_from = email_from
        self.smtp_server = smtp_server
        self.verify_url = verify_url

    def send_mail(self, token, email_to):
        message = self.message.replace(Email.TOKEN_REPLACE, token)
        message = message.replace(Email.EMAIL_VERIFY_URL_REPLACE, "%s?%s=%s" %
                                       (self.verify_url, Email.TOKEN_PARAM, token))
        msg = MIMEText(message)
        msg['Subject'] = self.subject
        msg['From'] = self.email_from
        msg['To'] = email_to
        s = smtplib.SMTP(self.smtp_server)
        s.send_message(msg)
        s.quit()


class JWTHandler(object):
    @staticmethod
    def key(jwt, keys):
        JWTHandler._verify_jwt(jwt, keys)
        jso = JWTHandler._unpack_jwt(jwt)
        idp = jso["idp"]
        id = jso["id"]
        return hashlib.sha512(idp + id)

    @staticmethod
    def _verify_jwt(jwt, keys):
        _jw = jws.factory(jwt)
        _jw.verify_compact(jwt, keys)

    @staticmethod
    def _unpack_jwt(jwt):
        _jwt = JWT().unpack(jwt)
        jso = _jwt.payload()
        if "id" not in jso or "attr" not in jso or "redirect_endpoint" not in jso:
            return None
        return jso


class AccountLinking(object):

    def __init__(self, db, keys, salt, email_sender):
        """

        :type db: ConsentDb
        :type keys: []
        :type ticket_ttl: int

        :param db:
        :param keys: Public keys to verify JWT signature.
        :param ticket_ttl: How long the ticket should live in seconds.
        :return:
        """
        self.db = db
        self.keys = keys
        self.salt = salt
        self.email_sender = email_sender

    def get_uuid(self, key):
        uuid = self.db.get_uuid(key)
        return uuid

    @staticmethod
    def create_token(value, salt):
        token = urlsafe_b64encode(
            hashlib.sha512((value + salt + str(mktime(gmtime())) + random.getrandbits(1024))
                           .encode()).hexdigest().encode()).decode()
        return token

    @staticmethod
    def create_hash(value, salt):
        hash = hashlib.sha512((value + salt).encode("UTF-8")).hexdigest()
        return hash

    def create_ticket(self, key, idp):
        ticket = AccountLinking.create_token(key, self.salt)
        data = TicketData(datetime.now, key, idp)
        self.db.save_uuid_request(ticket, data)
        return ticket

    def create_account_step1(self, email, ticket):
        token = AccountLinking.create_token(email, self.salt)
        token = "%s.%s" % (token, ticket)
        email_hash = self.create_hash(email, self.salt)
        email_data = EmailData(datetime.now, email_hash)
        data = self.db.save_email(token, email_data)
        self.email_sender.send_email_token(token, email)

    def create_account_step2(self, token):
        tokens = token.split(".")
        email_token_data = self.db.get_email(tokens[0])
        if email_token_data is None:
            raise ALserviceTokenError()
        return token

    def create_uuid(self):
        uuid = self.create_token(uuid4().urn)
        while self.get_uuid(uuid) is not None:
            uuid = self.create_token(uuid4().urn)
        return uuid

    def create_account_step3(self, token, pin):
        tokens = token.split(".")
        email_data = self.db.get_email(tokens[0])
        if email_data is None:
            raise ALserviceTokenError()
        email_data.pin = self.create_hash(pin, self.salt)
        email_data.timestamp = datetime.now
        self.db.remove_token(token)
        ticket_data = self.db.get_uuid_request(tokens[1])
        self.db.remove_ticket(tokens[1])
        uuid = self.create_uuid()
        self.db.save_email(email_data, uuid)
        self.db.save_uuid(ticket_data.key, ticket_data.idp, email_data.email_hash, uuid)

    def link_key(self, email, pin, ticket):
        email_hash = self.create_hash(email, self.salt)
        pin_hash = self.create_hash(pin, self.salt)
        uuid = self.db.get_user_uuid(email_hash, pin_hash)
        if uuid:
            ticket_data = self.db.get_uuid_request(ticket)
            self.db.remove_ticket(ticket)
            self.db.save_uuid(ticket_data.key, ticket_data.idp, email_hash, uuid)
        raise ALserviceAuthenticationError()
