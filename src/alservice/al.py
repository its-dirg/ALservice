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
                 email_sender_pin_recovery: Email = None, pin_verify: str = None, pin_empty: bool = True):
        """
        Constructor.
        :param trusted_keys: trusted public keys to verify JWT signatures
        :param db: database to use
        :param salt: salt to use when hashing identifiers
        :param email_sender_create_account: strategy for sending email for new account
        :param email_sender_pin_recovery: strategy for sending email for pin recovery
        :param pin_verify: regular expression for verifying pin codes
        :param pin_empty: whether to allow empty pin codes or not
        """
        self.pin_verify = None
        if pin_verify is not None:
            self.pin_verify = re.compile(pin_verify)

        self.trusted_keys = trusted_keys
        self.pin_empty = pin_empty
        self.db = db
        self.salt = salt
        self.email_sender_create_account = email_sender_create_account
        self.email_sender_pin_recovery = email_sender_pin_recovery

    def _verify_pin(self, pin) -> bool:
        """
        Verifies the given pin code against the required format.
        :param pin: pin to verify
        :return: True if the pin code is valid, otherwise False.
        """
        if pin is None:
            return False

        # pin code is empty and it's explicitly allowed
        if len(pin) == 0 and self.pin_empty:
            return True

        # pin code fulfills required format
        if self.pin_verify is None or self.pin_verify.match(pin):
            return True

        return False

    def get_uuid(self, key: str) -> str:
        """
        Gets the account id bound to the user identified by the key.
        :param key: user account key
        :return: a user id.
        """
        try:
            return self.db.get_uuid(key)
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.info("Key (%s) not existing in database, user must link this account!", key)
            raise ALserviceNoSuchKey() from error

    def _create_token(self, value: str) -> str:
        """
        Creates a token.
        The token is bound to the value, together with the creation time and a random number.

        :param value: token base
        :return: a token
        """
        token = urlsafe_b64encode(
            hashlib.sha512((value + self.salt + str(mktime(gmtime())) + str(random.getrandbits(1024)))
                           .encode()).hexdigest().encode()).decode()
        return token

    def _create_hash(self, value: str) -> str:
        """
        Hash a value with a salt
        :param value: The value to hash
        :return: the hashed value
        """
        hash_value = hashlib.sha512((value + self.salt).encode("UTF-8")).hexdigest()
        return hash_value

    def create_ticket(self, request: IdRequest):
        """
        Stores an account linking request, associated with the returned ticket.
        :param request: account linking request
        :return: the ticket associated with the request
        """
        ticket = self._create_token(request.key)
        self.db.save_ticket_state(ticket, request.key, request["idp"], request["redirect_endpoint"])
        return ticket

    def create_account_step1(self, email: str, ticket: str):
        """
        The first step of creating an account.
        A token is sent to the specified email. This token need to be provided in the next
        account creation step.
        :param email: email address to send the token
        :param ticket: ticket to bind the token to
        """
        try:
            self.db.get_ticket_state(ticket)
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Ticket is missing (%s)!", ticket)
            raise ALserviceTicketError() from error
        token = self._create_token(email)
        token_ticket = "%s.%s" % (token, ticket)
        email_hash = self._create_hash(email)
        self.db.save_token_state(token, email_hash)
        self.email_sender_create_account.send_mail(token_ticket, email)

    def _split_token(self, token: str) -> list:
        """
        Splits a combined token in to token and ticket
        :param token: combined token
        :return: token and ticket
        """
        if token is None:
            raise ALserviceTokenError()

        tokens = token.split(".")
        if len(tokens) != 2:
            LOGGER.exception("Incorrect token (%s)!", token)
            raise ALserviceTokenError()
        return tokens

    def create_account_step2(self, token: str):
        """
        The second step of creating an account.
        Verifies the token.
        :param token: token to verify
        :return: the verified token
        """
        tokens = self._split_token(token)
        try:
            self.db.get_ticket_state(tokens[1])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect ticket (%s)!", tokens[1])
            raise ALserviceTicketError() from error
        try:
            self.db.get_token_state(tokens[0])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect token (%s)!", tokens[0])
            raise ALserviceTokenError() from error
        return token

    def create_uuid(self) -> str:
        """
        Creates an uuid
        :return: the created uuid
        """
        uuid = self._create_token(uuid4().urn)
        try:
            while self.get_uuid(uuid):
                uuid = self._create_token(uuid4().urn)
        except ALserviceNoSuchKey:
            pass
        return uuid

    def get_redirect_url(self, token: str) -> str:
        """
        Gets the redirect endpoint bound to the ticket/token
        :param token: Key to redirect endpoint in db
        :return: the redirect endpoint.
        """
        ticket = token
        if "." in ticket:
            ticket = ticket.split(".")[1]
        ticket_state = self.db.get_ticket_state(ticket)
        return ticket_state.redirect

    def create_account_step3(self, token: str, pin: str = ""):
        """
        The third and last step of creating an account
        Approves the new account link and protects the account with a pin.
        :param token: the account creation token
        :param pin: pin code for the account
        """
        if not self._verify_pin(pin):
            raise ALserviceNotAValidPin()

        tokens = self._split_token(token)
        try:
            email_state = self.db.get_token_state(tokens[0])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect ticket (%s)!" % tokens[0])
            raise ALserviceTokenError() from error

        try:
            ticket_state = self.db.get_ticket_state(tokens[1])
        except ALserviceDbKeyDoNotExistsError as error:
            LOGGER.exception("Incorrect ticket (%s)!" % tokens[1])
            raise ALserviceTicketError() from error
        self.db.remove_ticket_state(tokens[1])
        self.db.remove_token_state(tokens[0])
        uuid = self.create_uuid()

        pin_hash = None
        if pin is not None:
            pin_hash = self._create_hash(pin)
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
        Links a new key to the account.
        :param email: the account email
        :param pin: the account pin code
        :param ticket: ticket for the key link information
        """
        try:
            email_hash = self._create_hash(email)
            pin_hash = self._create_hash(pin)
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
        :param email: the account email
        :param pin: the account pin code
        """
        try:
            email_hash = self._create_hash(email)
            pin_hash = self._create_hash(pin)
            self.db.verify_account(email_hash, pin_hash)
            token = self._create_token(email_hash)
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
        if not self._verify_pin(new_pin):
            raise ALserviceNotAValidPin("The new pin code was invalid")

        try:
            email_state = self.db.get_token_state(token)
            old_pin_hash = self._create_hash(old_pin)
            self.db.verify_account(email_state.email_hash, old_pin_hash)
            new_pin_hash = self._create_hash(new_pin)
            self.db.change_pin(email_state.email_hash, old_pin_hash, new_pin_hash)
        except Exception as error:
            LOGGER.exception("Unknown error while changing pin.")
            raise ALserviceAuthenticationError() from error
