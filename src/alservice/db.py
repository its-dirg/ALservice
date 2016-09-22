import hashlib
import json
import logging
from abc import abstractmethod, ABCMeta
from datetime import datetime

import dataset
from sqlalchemy.exc import IntegrityError

from alservice.exception import ALserviceDbKeyDoNotExistsError, ALserviceDbUnknownError, \
    ALserviceDbNotUniqueTokenError, ALserviceDbValidationError, ALserviceDbValueDoNotExistsError, \
    ALserviceDbError

LOGGER = logging.getLogger(__name__)


class TicketState(object):
    def __init__(self, timestamp: datetime, key: str, idp: str, redirect: str):
        """
        Constructor.
        :param timestamp: when the ticket state was created
        :param key: account key on which the ticket is based
        :param idp: which IdP the user is from
        :param redirect: URL to which the user should be redirected when account linking is completed
        """
        self.timestamp = timestamp
        self.key = key
        self.idp = idp
        self.redirect = redirect


class TokenState(object):
    def __init__(self, timestamp: datetime, email_hash: str):
        """
        Constructor.
        :param timestamp: when the token was created
        :param email_hash: hash value of the users account email address
        """
        self.timestamp = timestamp
        self.email_hash = email_hash


class AccountLinkingDB(metaclass=ABCMeta):
    TOKEN = "token"
    TICKET = "ticket"
    KEY = "key"
    IDP = "idp"
    REDIRECT = "redirect"
    EMAIL_HASH = "email_hash"
    PIN_HASH = "pin_hash"
    OLD_PIN_HASH = "old_%s" % PIN_HASH
    NEW_PIN_HASH = "new_%s" % PIN_HASH
    UUID = "uuid"

    @staticmethod
    def validation(attributes: dict):
        validation_message = ""
        if attributes is not None:
            for attr in attributes:
                if not isinstance(attributes[attr], str):
                    validation_message += "The value for %s is not allowed to be empty." % attr

                elif attributes[attr] is None or len(attributes[attr]) <= 0:
                    validation_message += "The type of %s must be string." % attr
        if len(validation_message) > 0:
            LOGGER.error("Attributes cannot be saved to the database since they are invalid. %s",
                         validation_message)
            raise ALserviceDbValidationError(validation_message)

    @abstractmethod
    def get_uuid(self, key: str) -> str:
        """

        :param key: A key that uniquely identifies an Idp and the users identification on that IdP.
        :return: An accounts uuid.
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.KEY: key
            }
        )

    @abstractmethod
    def save_ticket_state(self, ticket: str, key: str, idp: str, redirect: str):
        """

        :param ticket: A uuid that represents a state.
        :param key: The account linking question asked by the client
        :param idp: The IDP which you want to connect to a user
        :param redirect: An URL to which the user should be redirected when flow is completed
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.TICKET: ticket,
                AccountLinkingDB.KEY: key,
                AccountLinkingDB.IDP: idp,
                AccountLinkingDB.REDIRECT: redirect,
            }
        )

    @abstractmethod
    def save_token_state(self, token: str, email_hash: str):
        """

        :param token: A uuid that represents a state.
        :param email_hash: A hash value of an email address
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.TOKEN: token,
                AccountLinkingDB.EMAIL_HASH: email_hash
            }
        )

    @abstractmethod
    def get_token_state(self, token: str) -> TokenState:
        """

        :param token: Identifier for a token in the database
        :return: Token state
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.TOKEN: token
            }
        )

    @abstractmethod
    def get_ticket_state(self, ticket: str) -> TicketState:
        """

        :param ticket: Identifier for a ticket in the database
        :return: Ticket state
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.TICKET: ticket
            }
        )

    @abstractmethod
    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        """

        :param email_hash: A hash value of an email address
        :param pin_hash: Hash value of a pin code
        :param uuid: Unique identifier for the user
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.EMAIL_HASH: email_hash,
                AccountLinkingDB.PIN_HASH: pin_hash,
                AccountLinkingDB.UUID: uuid
            }
        )

    @abstractmethod
    def create_link(self, key: str, idp: str, email_hash: str):
        """

        :param key: The account linking question asked by the client
        :param idp: The IDP which you want to connect to a user
        :param email_hash: A hash value of an email address
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.KEY: key,
                AccountLinkingDB.IDP: idp,
                AccountLinkingDB.EMAIL_HASH: email_hash
            }
        )

    @abstractmethod
    def remove_link(self, email_hash: str, idp: str):
        """

        :param email_hash: A hash value of an email address
        :param idp: The IDP which you want to connect to a user
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.IDP: idp,
                AccountLinkingDB.EMAIL_HASH: email_hash
            }
        )

    @abstractmethod
    def verify_account(self, email_hash: str, pin_hash: str):
        """
        :param email_hash: A hash value of an email address
        :param pin_hash: Hash value of a users pin code
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.EMAIL_HASH: email_hash,
                AccountLinkingDB.PIN_HASH: pin_hash
            }
        )

    @abstractmethod
    def remove_ticket_state(self, ticket: str):
        """
        :param ticket: The ticket to remove
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.TICKET: ticket
            }
        )

    @abstractmethod
    def remove_token_state(self, token: str):
        """
        :param token: THe token to remove
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.TOKEN: token
            }
        )

    @abstractmethod
    def remove_account(self, email_hash: str):
        """
        :param email_hash: A hash value of an email address
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.EMAIL_HASH: email_hash
            }
        )

    @abstractmethod
    def change_pin(self, email_hash: str, old_pin_hash: str, new_pin_hash: str):
        """
        :param email_hash: A hash value of an email address
        :param old_pin_hash: Hash value of the old pin code
        :param new_pin_hash: Hash value of the new pin code
        """
        AccountLinkingDB.validation(
            {
                AccountLinkingDB.EMAIL_HASH: email_hash,
                AccountLinkingDB.OLD_PIN_HASH: old_pin_hash,
                AccountLinkingDB.NEW_PIN_HASH: new_pin_hash,
            }
        )


ACCOUNT_TO_LINK_KEY = "key"
ACCOUNT_TO_LINK_LINK = "link"


class ALDatasetDatabase(AccountLinkingDB):
    """
    Implementation using the `dataset` library.
    """
    TICKET_TABLE_NAME = "ticket_table"
    TOKEN_TABLE_NAME = "token_table"
    ACCOUNT_TABLE_NAME = "account_table"
    KEY_TO_LINK_TABLE_NAME = "key_to_link_table"
    LINK_TO_KEY_TABLE_NAME = "link_to_key_table"
    ACCOUNT_TO_LINK_TABLE_NAME = "account_to_link_table"

    def __init__(self, database_path=None):
        if database_path:
            self.c_db = dataset.connect(database_path)
        else:
            self.c_db = dataset.connect("sqlite:///:memory:")

        self.ticket_table = self.c_db.get_table(
            self.TICKET_TABLE_NAME,
            primary_id="ticket",
            primary_type="String(250)"
        )
        self.token_table = self.c_db.get_table(
            self.TOKEN_TABLE_NAME,
            primary_id="token",
            primary_type="String(250)"
        )
        self.account_table = self.c_db.get_table(
            self.ACCOUNT_TABLE_NAME,
            primary_id="email",
            primary_type="String(250)"
        )
        self.key_to_link_table = self.c_db.get_table(
            self.KEY_TO_LINK_TABLE_NAME,
            primary_id="key",
            primary_type="String(250)"
        )
        self.link_to_key_table = self.c_db.get_table(
            self.LINK_TO_KEY_TABLE_NAME,
            primary_id="link",
            primary_type="String(250)"
        )
        self.account_to_link_table = self.c_db.get_table(
            self.ACCOUNT_TO_LINK_TABLE_NAME,
            primary_id="email",
            primary_type="String(250)"
        )

    def get_uuid(self, key: str) -> str:
        """
        See ALdatabase#get_uuid
        """
        super(ALDatasetDatabase, self).get_uuid(key)

        if not self.key_to_link_table.find_one(key=key):
            raise ALserviceDbKeyDoNotExistsError()

        row = self.key_to_link_table.find_one(key=key)

        try:
            email_hash = row["email"]
        except KeyError:
            email_hash = None

        account = self.account_table.find_one(email=email_hash)
        if not account:
            raise ALserviceDbKeyDoNotExistsError()

        uuid = account["uuid"]

        if uuid is None:
            raise ALserviceDbUnknownError()
        return uuid

    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        """
        See ALdatabase#create_account
        """
        super(ALDatasetDatabase, self).create_account(email_hash, pin_hash, uuid)
        if self.account_table.find_one(email=email_hash):
            raise ALserviceDbNotUniqueTokenError()
        _dict_account = {
            "email": email_hash,
            "pin": pin_hash,
            "uuid": uuid,
            "timestamp": str(datetime.now())
        }
        self.account_table.insert(_dict_account)

    def _create_link(self, email_hash: str, idp: str):
        link = hashlib.sha512(idp.encode() + email_hash.encode()).hexdigest()
        return link

    def create_link(self, key: str, idp: str, email_hash: str):
        super(ALDatasetDatabase, self).create_link(key, idp, email_hash)
        link = self._create_link(email_hash, idp)
        self.remove_link(email_hash, idp)
        _dict_key_to_link = {
            "key": key,
            "idp": idp,
            "email": email_hash
        }

        _account_to_link_data = {
            "key": key,
            "link": link,
        }

        _dict_account_to_link = {
            "email": email_hash,
            "data": json.dumps([_account_to_link_data])
        }

        _dict_link_to_key = {
            "link": link,
            "key": key
        }

        try:
            result = self.account_to_link_table.find_one(email=email_hash)
            if result:
                account_list = json.loads(result["data"])
                account_list.append(_account_to_link_data)
                _dict_account_to_link['data'] = json.dumps(account_list)
            self.account_to_link_table.upsert(
                _dict_account_to_link,
                ["email"]
            )
            self.key_to_link_table.insert(_dict_key_to_link)
            self.link_to_key_table.insert(_dict_link_to_key)
        except IntegrityError as err:
            raise ALserviceDbNotUniqueTokenError()

    def remove_link(self, email_hash: str, idp: str):
        super(ALDatasetDatabase, self).remove_link(email_hash, idp)
        link = self._create_link(email_hash, idp)
        result = self.link_to_key_table.find_one(link=link)
        if result:
            key = result["key"]
            self.key_to_link_table.delete(key=key)
            self.link_to_key_table.delete(link=link)

    def get_ticket_state(self, result: str) -> TicketState:
        super(ALDatasetDatabase, self).get_ticket_state(result)
        result = self.ticket_table.find_one(ticket=result)
        if not result:
            raise ALserviceDbKeyDoNotExistsError()
        key = result["key"]
        idp = result["idp"]
        timestamp = result["timestamp"]
        redirect = result["redirect_url"]
        ticket_state = TicketState(timestamp, key, idp, redirect)
        return ticket_state

    def save_ticket_state(self, ticket: str, key: str, idp: str, redirect: str):
        super(ALDatasetDatabase, self).save_ticket_state(ticket, key, idp, redirect)
        if self.ticket_table.find_one(ticket=ticket):
            raise ALserviceDbNotUniqueTokenError()
        _dict = {
            "ticket": ticket,
            "idp": idp,
            "key": key,
            "redirect_url": redirect,
            "timestamp": datetime.now()
        }
        self.ticket_table.insert(_dict)

    def save_token_state(self, token: str, email_hash: str):
        super(ALDatasetDatabase, self).save_token_state(token, email_hash)
        if self.token_table.find_one(token=token):
            raise ALserviceDbNotUniqueTokenError()
        _dict = {
            "token": token,
            "email": email_hash,
            "timestamp": datetime.now()
        }
        self.token_table.insert(_dict)

    def get_token_state(self, token: str) -> TokenState:
        super(ALDatasetDatabase, self).get_token_state(token)
        result = self.token_table.find_one(token=token)
        if not result:
            raise ALserviceDbKeyDoNotExistsError()
        email_hash = result["email"]
        timestamp = result["timestamp"]
        email_state = TokenState(timestamp, email_hash)
        return email_state

    def verify_account(self, email_hash: str, pin_hash: str):
        super(ALDatasetDatabase, self).verify_account(email_hash, pin_hash)
        account = self.account_table.find_one(email=email_hash)
        if not account:
            raise ALserviceDbKeyDoNotExistsError()
        if pin_hash != account["pin"]:
            raise ALserviceDbValueDoNotExistsError()

    def remove_ticket_state(self, ticket: str):
        super(ALDatasetDatabase, self).remove_ticket_state(ticket)
        self.ticket_table.delete(ticket=ticket)

    def remove_token_state(self, token: str):
        super(ALDatasetDatabase, self).remove_token_state(token)
        self.token_table.delete(token=token)

    def remove_account(self, email_hash: str):
        super(ALDatasetDatabase, self).remove_account(email_hash)
        self.account_table.delete(email=email_hash)
        _dict_account_to_link = self.account_to_link_table.find_one(email=email_hash)
        if _dict_account_to_link:
            account_to_link_list = json.loads(_dict_account_to_link['data'])
            for tmp_link in account_to_link_list:
                self.link_to_key_table.delete(link=tmp_link["link"])
                self.key_to_link_table.delete(key=tmp_link["key"])
            self.account_to_link_table.delete(email=email_hash)

    def _get_account_link_data(self, email_hash: str) -> list:
        result = self.account_to_link_table.find_one(email=email_hash)
        if result:
            return json.loads(result['data'])
        return None

    def change_pin(self, email_hash: str, old_pin_hash: str, new_pin_hash: str):
        super(ALDatasetDatabase, self).change_pin(email_hash, old_pin_hash, new_pin_hash)
        self.verify_account(email_hash, old_pin_hash)
        row = self.account_table.find_one(email=email_hash)
        row["pin"] = new_pin_hash
        self.account_table.upsert(row, ["email"])
