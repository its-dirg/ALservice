from base64 import urlsafe_b64encode
from email.header import Header
from email.mime.text import MIMEText
import hashlib
import random
import smtplib
from time import mktime, gmtime
from uuid import uuid4
from jwkest import jws
from jwkest.jwt import JWT
from alservice.db import ALdatabase
from alservice.exception import ALserviceTokenError, ALserviceAuthenticationError, \
    ALserviceDbKeyDoNotExistsError


class Email(object):
    TOKEN_REPLACE = "<<token>>"
    EMAIL_VERIFY_URL_REPLACE = "<<email_verify_url>>"
    TOKEN_PARAM = "token"

    def __init__(self, subject: str, message: str, email_from: str, smtp_server: str,
                 verify_url: str):
        self.subject = subject
        """:type: str"""

        self.message = message
        """:type: str"""

        self.email_from = email_from
        """:type: str"""

        self.smtp_server = smtp_server
        """:type: str"""

        self.verify_url = verify_url
        """:type: str"""

    def send_mail(self, token: str, email_to: str):
        message = self.message.replace(Email.TOKEN_REPLACE, token)
        message = message.replace(Email.EMAIL_VERIFY_URL_REPLACE, "%s?%s=%s" %
                                       (self.verify_url, Email.TOKEN_PARAM, token))
        msg = MIMEText(message, "plain", "utf-8")
        msg['Subject'] = Header(self.subject, 'utf-8').encode()
        msg['From'] = "\"{sender}\" <{sender}>".format(sender=self.email_from)
        msg['To'] = email_to
        s = smtplib.SMTP(self.smtp_server)
        failed = s.sendmail(self.email_from, email_to, msg.as_string())
        s.quit()



class JWTHandler(object):
    @staticmethod
    def key(jwt: str, keys: list):
        """

        :param jwt:
        :param keys:
        :return:
        """
        JWTHandler._verify_jwt(jwt, keys)
        jso = JWTHandler._unpack_jwt(jwt)
        idp = jso["idp"]
        id = jso["id"]
        return hashlib.sha512((idp + id).encode()).hexdigest()

    @staticmethod
    def _verify_jwt(jwt: str, keys: list):
        """
        :type keys: list[str]

        :param jwt:
        :param keys:
        :return:
        """
        _jw = jws.factory(jwt)
        _jw.verify_compact(jwt, keys)

    @staticmethod
    def _unpack_jwt(jwt: str):
        _jwt = JWT().unpack(jwt)
        jso = _jwt.payload()
        if "id" not in jso or "idp" not in jso or "redirect_endpoint" not in jso:
            return None
        return jso


class AccountLinking(object):

    def __init__(self, db: ALdatabase, keys: list, salt: str, email_sender: Email):
        """

        :type keys: list[str]

        :param db:
        :param keys: Public keys to verify JWT signature.
        :param ticket_ttl: How long the ticket should live in seconds.
        :return:
        """

        self.db = db
        """:type: ALdatabase"""

        self.keys = keys
        """:type: list[str]"""

        self.salt = salt
        """:type: str"""

        self.email_sender = email_sender
        """:type: Email"""

    def get_uuid(self, key: str):
        uuid = self.db.get_uuid(key)
        return uuid

    @staticmethod
    def create_token(value: str, salt: str):
        token = urlsafe_b64encode(
            hashlib.sha512((value + salt + str(mktime(gmtime())) + str(random.getrandbits(1024)))
                           .encode()).hexdigest().encode()).decode()
        return token

    @staticmethod
    def create_hash(value: str, salt: str):
        hash = hashlib.sha512((value + salt).encode("UTF-8")).hexdigest()
        return hash

    def create_ticket(self, key: str, idp: str, redirect: str):
        ticket = AccountLinking.create_token(key, self.salt)
        self.db.save_ticket_state(ticket, key, idp, redirect)
        return ticket

    def create_account_step1(self, email: str, ticket: str):
        token = AccountLinking.create_token(email, self.salt)
        token_ticket = "%s.%s" % (token, ticket)
        email_hash = self.create_hash(email, self.salt)
        self.db.save_token_state(token, email_hash)
        self.email_sender.send_mail(token_ticket, email)

    def create_account_step2(self, token: str):
        tokens = token.split(".")
        email_state = self.db.get_token_state(tokens[0])
        if email_state is None:
            raise ALserviceTokenError()
        return token

    def create_uuid(self):
        uuid = AccountLinking.create_token(uuid4().urn, self.salt)
        try:
            while self.get_uuid(uuid):
                uuid = AccountLinking.create_token(uuid4().urn, self.salt)
        except ALserviceDbKeyDoNotExistsError:
            pass
        return uuid

    def get_redirect_url(self, token: str):
        ticket = token
        if "." in ticket:
            ticket = ticket.split(".")[1]
        ticket_state = self.db.get_ticket_state(ticket)
        return ticket_state.redirect

    def create_account_step3(self, token: str, pin: str):
        tokens = token.split(".")
        email_data = self.db.get_token_state(tokens[0])
        if email_data is None:
            raise ALserviceTokenError()
        pin_hash = self.create_hash(pin, self.salt)
        self.db.remove_token_state(tokens[0])
        ticket_data = self.db.get_ticket_state(tokens[1])
        self.db.remove_ticket_state(tokens[1])
        uuid = self.create_uuid()
        self.db.create_account(email_data.email_hash, pin_hash, uuid)
        self.db.create_link(ticket_data.key, ticket_data.idp, email_data.email_hash)

    def link_key(self, email: str, pin: str, ticket: str):
        try:
            email_hash = self.create_hash(email, self.salt)
            pin_hash = self.create_hash(pin, self.salt)
            self.db.verify_account(email_hash, pin_hash)
            ticket_data = self.db.get_ticket_state(ticket)
            self.db.remove_ticket_state(ticket)
            self.db.create_link(ticket_data.key, ticket_data.idp, email_hash)
        except Exception as error:
            raise ALserviceAuthenticationError() from error

    def change_pin(self, email: str, old_pin: str, new_pin: str):
        try:
            email_hash = self.create_hash(email, self.salt)
            old_pin_hash = self.create_hash(old_pin, self.salt)
            new_pin_hash = self.create_hash(new_pin, self.salt)
            self.db.change_pin(email_hash, old_pin_hash, new_pin_hash)
        except Exception as error:
            raise ALserviceAuthenticationError() from error
