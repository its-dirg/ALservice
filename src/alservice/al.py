"""
Module for handling account linking
"""
import hashlib
import logging
import random
import re
from base64 import urlsafe_b64encode
from time import mktime, gmtime
from uuid import uuid4

import jwkest
from jwkest import jws

from alservice.db import ALdatabase
from alservice.exception import ALserviceTokenError, ALserviceAuthenticationError, \
    ALserviceDbKeyDoNotExistsError, ALserviceTicketError, ALserviceDbNotUniqueTokenError, \
    ALserviceAccountExists, ALserviceNoSuchKey, ALserviceNotAValidPin
from alservice.mail import Email

LOGGER = logging.getLogger(__name__)


class IdRequest:
    def __init__(self, data: dict):
        mandatory_params = {"id", "idp", "redirect_endpoint"}
        if not mandatory_params.issubset(set(data.keys())):
            # missing required info
            raise ValueError(
                "Incorrect account linking request, missing some mandatory params".format(mandatory_params))
        self.data = data

    @property
    def key(self):
        """
        Retrieve the hash key for the idp/id pair
        :rtype: str
        :param jso: The unpacked jwt
        :return: A key
        """
        return hashlib.sha512((self.data["idp"] + self.data["id"]).encode()).hexdigest()

    def __getitem__(self, item):
        return self.data[item]

    def __str__(self):
        return "{} -> {}".format(self.key, str(self.data))


class AccountLinking(object):
    """
    Handles account linking logic
    """

    def __init__(self, trusted_keys: list, db: ALdatabase, salt: str, email_sender_create_account: Email,
                 email_sender_pin_recovery: Email = None, pin_verify: str = None,
                 pin_empty: bool = True):
        """
        :type keys: list[str]

        :param db: Database to use
        :param keys: Public keys to verify JWT signature.
        :return:
        """
        self.pin_verify = None
        if pin_verify is not None:
            self.pin_verify = re.compile(pin_verify)

        self.trusted_keys = trusted_keys

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
        """
        Verifies the given pin format
        :param pin: The pin to verify
        """
        if pin is None:
            LOGGER.warn("User entered wrong pin!")
            raise ALserviceNotAValidPin()
        if self.pin_empty and len(pin) == 0:
            return
        if self.pin_verify is None or self.pin_verify.match(pin):
            return
        LOGGER.warn("User entered wrong pin!")
        raise ALserviceNotAValidPin()

    def get_uuid(self, key: str):
        """
        Gets the account id bound to the user identified in the request.
        :param key: user account key
        :return: a user id.
        """
        try:
            return self.db.get_uuid(key)
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.info("Key (%s) not existing in database, user must link this account!", key)
            raise ALserviceNoSuchKey() from error

    @staticmethod
    def create_token(value: str, salt: str):
        """
        Create a hashed, urlsafe, token. The hash is also based on time and random number.
        :rtype: str

        :param value: token base
        :param salt: A salt for the hashing
        :return: A token
        """
        token = urlsafe_b64encode(
            hashlib.sha512((value + salt + str(mktime(gmtime())) + str(random.getrandbits(1024)))
                           .encode()).hexdigest().encode()).decode()
        return token

    @staticmethod
    def create_hash(value: str, salt: str):
        """
        Hash a value with a salt
        :rtype: str
        :param value: The value to hash
        :param salt: A salt for the hash
        :return: the hashed value
        """
        hash_value = hashlib.sha512((value + salt).encode("UTF-8")).hexdigest()
        return hash_value

    def create_ticket(self, key: str, idp: str, redirect: str):
        """
        Save a key, idp and redirect_endpoint to the database with the returned ticket as key.
        :param key: The key link for the al
        :param idp: The linked idp
        :param redirect: The redirect after approval
        :return: A ticket (a key to the saved values)
        """
        ticket = AccountLinking.create_token(key, self.salt)
        self.db.save_ticket_state(ticket, key, idp, redirect)
        return ticket

    def create_account_step1(self, email: str, ticket: str):
        """
        The first step of creating an account.
        A token is sent to the specified email. This token need to be provided in the next
        account creation step.
        :param email: Email address to send the token.
        :param ticket: Needs a ticket to bind the token
        """
        try:
            self.db.get_ticket_state(ticket)
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Ticket is missing (%s)!" % ticket)
            raise ALserviceTicketError() from error
        token = AccountLinking.create_token(email, self.salt)
        token_ticket = "%s.%s" % (token, ticket)
        email_hash = self.create_hash(email, self.salt)
        self.db.save_token_state(token, email_hash)
        self.email_sender_create_account.send_mail(token_ticket, email)

    @staticmethod
    def _split_token(token: str):
        """
        Split a combined token in to token and ticket
        :rtype: (str, str)
        :param token: combined token
        :return: token and ticket
        """
        try:
            tokens = token.split(".")
        except Exception as error:
            LOGGER.exception("Incorrect token (%s)!" % token)
            raise ALserviceTokenError() from error
        if tokens is None or len(tokens) != 2:
            LOGGER.exception("Incorrect token (%s)!" % token)
            raise ALserviceTokenError()
        return tokens

    def create_account_step2(self, token: str):
        """
        The second step of creating an account.
        Verifies the token
        :param token: Token to verify
        :return: The same token
        """
        tokens = AccountLinking._split_token(token)
        try:
            self.db.get_ticket_state(tokens[1])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect ticket (%s)!" % tokens[1])
            raise ALserviceTicketError() from error
        try:
            email_state = self.db.get_token_state(tokens[0])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect token (%s)!" % tokens[0])
            raise ALserviceTokenError() from error
        return token

    def create_uuid(self):
        """
        Create an uuid
        :return: The created uuid
        """
        uuid = AccountLinking.create_token(uuid4().urn, self.salt)
        try:
            while self.get_uuid(uuid):
                uuid = AccountLinking.create_token(uuid4().urn, self.salt)
        except ALserviceNoSuchKey:
            pass
        return uuid

    def get_redirect_url(self, token: str):
        """
        Get the redirect endpoint bound to the ticket/token
        :param token: Key to redirect endpoint in db
        :return: the redirect endpoint
        """
        ticket = token
        if "." in ticket:
            ticket = ticket.split(".")[1]
        ticket_state = self.db.get_ticket_state(ticket)
        return ticket_state.redirect

    def create_account_step3(self, token: str, pin: str = ""):
        """
        The third and last step of creating an account (And approving the new key link)
        :param token: The account creation token
        :param pin: Password for the account
        """
        self.verify_pin(pin)
        tokens = AccountLinking._split_token(token)
        try:
            email_state = self.db.get_token_state(tokens[0])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect ticket (%s)!" % tokens[0])
            raise ALserviceTokenError() from error
        pin_hash = None
        if pin is not None:
            pin_hash = self.create_hash(pin, self.salt)
        try:
            ticket_state = self.db.get_ticket_state(tokens[1])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect ticket (%s)!" % tokens[1])
            raise ALserviceTicketError() from error
        self.db.remove_ticket_state(tokens[1])
        self.db.remove_token_state(tokens[0])
        uuid = self.create_uuid()
        try:
            self.db.create_account(email_state.email_hash, pin_hash, uuid)
        except ALserviceDbNotUniqueTokenError as error:
            LOGGER.exception("Incorrect token (%s)" % token)
            raise ALserviceAccountExists() from error
        try:
            self.db.create_link(ticket_state.key, ticket_state.idp, email_state.email_hash)
        except ALserviceDbNotUniqueTokenError as error:
            LOGGER.exception("Incorrect token (%s)" % token)
            raise ALserviceAccountExists() from error

    def link_key(self, email: str, pin: str, ticket: str):
        """
        Link a new key to the account.
        :param email: The account email (Username)
        :param pin: The account pin (Password)
        :param ticket: The ticket for the key link information
        """
        try:
            email_hash = self.create_hash(email, self.salt)
            pin_hash = self.create_hash(pin, self.salt)
            self.db.verify_account(email_hash, pin_hash)
            ticket_data = self.db.get_ticket_state(ticket)
            self.db.remove_ticket_state(ticket)
            self.db.create_link(ticket_data.key, ticket_data.idp, email_hash)
        except Exception as error:
            LOGGER.exception("User is not authentication due to an unknown error.")
            raise ALserviceAuthenticationError() from error

    def change_pin_step1(self, email: str, pin: str):
        """
        The first step of changing an account pin.
        Sends a token to the account email address
        :param email: Account email (Username)
        :param pin: Password
        """
        try:
            email_hash = self.create_hash(email, self.salt)
            pin_hash = self.create_hash(pin, self.salt)
            self.db.verify_account(email_hash, pin_hash)
            token = AccountLinking.create_token(email_hash, self.salt)
            self.db.save_token_state(token, email_hash)
            self.email_sender_pin_recovery.send_mail(token, email)
        except Exception as error:
            LOGGER.exception("Unknown error while changing pin.")
            raise ALserviceAuthenticationError() from error

    def change_pin_step2(self, token: str, old_pin: str, new_pin: str):
        """
        Second and last step in changing the account password.

        :param token: The token given in step one
        :param old_pin: The old password
        :param new_pin: The new password
        """
        try:
            self.verify_pin(new_pin)
            email_state = self.db.get_token_state(token)
            old_pin_hash = self.create_hash(old_pin, self.salt)
            self.db.verify_account(email_state.email_hash, old_pin_hash)
            new_pin_hash = self.create_hash(new_pin, self.salt)
            self.db.change_pin(email_state.email_hash, old_pin_hash, new_pin_hash)
        except Exception as error:
            LOGGER.exception("Unknown error while changing pin.")
            raise ALserviceAuthenticationError() from error
