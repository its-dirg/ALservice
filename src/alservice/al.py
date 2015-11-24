from abc import abstractmethod
from base64 import urlsafe_b64encode
from email.header import Header
from email.mime.text import MIMEText
import hashlib
import random
import smtplib
import re
from time import mktime, gmtime
from uuid import uuid4
from jwkest import jws
from jwkest.jwt import JWT
from alservice.db import ALdatabase
from alservice.exception import ALserviceTokenError, ALserviceAuthenticationError, \
    ALserviceDbKeyDoNotExistsError, ALserviceTicketError, ALserviceDbNotUniqueTokenError, \
    ALserviceAccountExists, ALserviceNoSuchKey, ALserviceNotAValidPin


class Email(object):
    @abstractmethod
    def send_mail(self, token: str, email_to: str):
        pass


class EmailSmtp(Email):
    TOKEN_REPLACE = "<<token>>"

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
        message = self.message.replace(EmailSmtp.TOKEN_REPLACE, token)
        msg = MIMEText(message, "plain", "utf-8")
        msg['Subject'] = Header(self.subject, 'utf-8').encode()
        msg['From'] = "\"{sender}\" <{sender}>".format(sender=self.email_from)
        msg['To'] = email_to
        s = smtplib.SMTP(self.smtp_server)
        failed = s.sendmail(self.email_from, email_to, msg.as_string())
        s.quit()


class JWTHandler(object):
    @staticmethod
    def key(jso):
        """

        :param jwt:
        :param keys:
        :return:
        """
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
    def unpack_jwt(jwt: str, keys: list):
        JWTHandler._verify_jwt(jwt, keys)
        _jwt = JWT().unpack(jwt)
        jso = _jwt.payload()
        if "id" not in jso or "idp" not in jso or "redirect_endpoint" not in jso:
            return None
        return jso


class AccountLinking(object):

    def __init__(self, db: ALdatabase, salt: str, email_sender_create_account: Email,
                 email_sender_pin_recovery: Email=None, pin_verify: str=None, pin_empty: bool=True):
        """

        :type keys: list[str]

        :param db:
        :param keys: Public keys to verify JWT signature.
        :param ticket_ttl: How long the ticket should live in seconds.
        :return:
        """
        self.pin_verify = None
        if pin_verify is not None:
            self.pin_verify = re.compile(pin_verify)

        self.pin_empty = pin_empty
        """:type: str"""

        self.db = db
        """:type: ALdatabase"""

        self.salt = salt
        """:type: str"""

        self.email_sender_create_account = email_sender_create_account
        """:type: Email"""

        self.email_sender_pin_recovery = email_sender_pin_recovery
        """:type: Email"""

    def verify_pin(self, pin):
        if pin is None:
            raise ALserviceNotAValidPin()
        if self.pin_empty and len(pin) == 0:
            return
        if self.pin_verify is None or self.pin_verify.match(pin):
            return
        raise ALserviceNotAValidPin()

    def get_uuid(self, key: str):
        try:
            uuid = self.db.get_uuid(key)
        except ALserviceDbKeyDoNotExistsError as error:
            raise ALserviceNoSuchKey() from error
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
        try:
            self.db.get_ticket_state(ticket)
        except ALserviceDbKeyDoNotExistsError as error:
            raise ALserviceTicketError() from error
        token = AccountLinking.create_token(email, self.salt)
        token_ticket = "%s.%s" % (token, ticket)
        email_hash = self.create_hash(email, self.salt)
        self.db.save_token_state(token, email_hash)
        self.email_sender_create_account.send_mail(token_ticket, email)

    @staticmethod
    def _split_token(token):
        try:
            tokens = token.split(".")
        except Exception as error:
            raise ALserviceTokenError() from error
        if tokens is None or len(tokens) != 2:
            raise ALserviceTokenError()
        return tokens

    def create_account_step2(self, token: str):
        tokens = AccountLinking._split_token(token)
        try:
            self.db.get_ticket_state(tokens[1])
        except ALserviceDbKeyDoNotExistsError as error:
            raise ALserviceTicketError() from error
        try:
            email_state = self.db.get_token_state(tokens[0])
        except ALserviceDbKeyDoNotExistsError as error:
            raise ALserviceTokenError() from error
        return token

    def create_uuid(self):
        uuid = AccountLinking.create_token(uuid4().urn, self.salt)
        try:
            while self.get_uuid(uuid):
                uuid = AccountLinking.create_token(uuid4().urn, self.salt)
        except ALserviceNoSuchKey:
            pass
        return uuid

    def get_redirect_url(self, token: str):
        ticket = token
        if "." in ticket:
            ticket = ticket.split(".")[1]
        ticket_state = self.db.get_ticket_state(ticket)
        return ticket_state.redirect

    def create_account_step3(self, token: str, pin: str=""):
        self.verify_pin(pin)
        tokens = AccountLinking._split_token(token)
        try:
            email_state = self.db.get_token_state(tokens[0])
        except ALserviceDbKeyDoNotExistsError as error:
            raise ALserviceTokenError() from error
        pin_hash = None
        if pin is not None:
            pin_hash = self.create_hash(pin, self.salt)
        try:
            ticket_state = self.db.get_ticket_state(tokens[1])
        except ALserviceDbKeyDoNotExistsError as error:
            raise ALserviceTicketError() from error
        self.db.remove_ticket_state(tokens[1])
        self.db.remove_token_state(tokens[0])
        uuid = self.create_uuid()
        try:
            self.db.create_account(email_state.email_hash, pin_hash, uuid)
        except ALserviceDbNotUniqueTokenError as error:
            raise ALserviceAccountExists() from error
        try:
            self.db.create_link(ticket_state.key, ticket_state.idp, email_state.email_hash)
        except ALserviceDbNotUniqueTokenError as error:
            raise ALserviceAccountExists() from error

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

    def change_pin_step1(self, email: str, pin: str):
        try:
            email_hash = self.create_hash(email, self.salt)
            pin_hash = self.create_hash(pin, self.salt)
            self.db.verify_account(email_hash, pin_hash)
            token = AccountLinking.create_token(email_hash, self.salt)
            self.db.save_token_state(token, email_hash)
            self.email_sender_create_account.send_mail(token, email)
        except Exception as error:
            raise ALserviceAuthenticationError() from error

    def change_pin_step2(self, token: str, old_pin: str, new_pin: str):
        try:
            self.verify_pin(new_pin)
            email_state = self.db.get_token_state(token)
            old_pin_hash = self.create_hash(old_pin, self.salt)
            self.db.verify_account(email_state.email_hash, old_pin_hash)
            new_pin_hash = self.create_hash(new_pin, self.salt)
            self.db.change_pin(email_state.email_hash, old_pin_hash, new_pin_hash)
        except Exception as error:
            raise ALserviceAuthenticationError() from error
