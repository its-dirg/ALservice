import hashlib
import json
import logging
from abc import abstractmethod
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


class AccountLinkingDB(object):
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
            {
                AccountLinkingDB.TICKET: ticket
            }
        )

    @abstractmethod
    def remove_token_state(self, token: str):
        """
        :param token: THe token to remove
        """
        ALDictDatabase.validation(
            {
                AccountLinkingDB.TOKEN: token
            }
        )

    @abstractmethod
    def remove_account(self, email_hash: str):
        """
        :param email_hash: A hash value of an email address
        """
        ALDictDatabase.validation(
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
        ALDictDatabase.validation(
            {
                AccountLinkingDB.EMAIL_HASH: email_hash,
                AccountLinkingDB.OLD_PIN_HASH: old_pin_hash,
                AccountLinkingDB.NEW_PIN_HASH: new_pin_hash,
            }
        )


class ALDictDatabase(AccountLinkingDB):
    TICKET_TICKET_PRIMARY = "ticket"
    TICKET_TIMESTAMP = "timestamp"
    TICKET_KEY = "key"
    TICKET_IDP = "idp"
    TICKET_REDIRECT_URL = "redirect"

    TOKEN_TOKEN_PRIMARY = "token"
    TOKEN_TIMESTAMP = "timestamp"
    TOKEN_EMAIL_HASH = "email"

    ACCOUNT_EMAIL_HASH_PRIMARY = "email"
    ACCOUNT_UUID = "uuid"
    ACCOUNT_PIN_HASH = "pin"
    ACCOUNT_TIMESTAMP = "timestamp"

    KEY_TO_LINK_KEY_PRIMARY = "key"
    KEY_TO_LINK_IDP = "idp"
    KEY_TO_LINK_EMAIL_HASH = "email"

    LINK_TO_KEY_LINK_PRIMARY = "link"
    LINK_TO_KEY_KEY = "key"

    ACCOUNT_TO_LINK_EMAIL_HASH_PRIMARY = "email"
    ACCOUNT_TO_LINK_KEY = "key"
    ACCOUNT_TO_LINK_LINK = "link"

    def __init__(self):
        self.ticket = {}
        """:type: dict[str, dict[str, str | timestamp]]"""

        self.token = {}
        """:type: dict[str, dict[str, str]]"""

        self.account = {}
        """:type: dict[str, dict[str, str]]"""

        self.key_to_link = {}
        """:type: dict[str, dict[str, str]]"""

        self.link_to_key = {}
        """:type: dict[str, str]"""

        self.account_to_link = {}
        """:type: dict[str, list[dict[str, str]]]"""

    def get_uuid(self, key: str) -> str:
        """
        See ALdatabase#get_uuid
        """
        try:
            super(ALDictDatabase, self).get_uuid(key)
            if key not in self.key_to_link:
                raise ALserviceDbKeyDoNotExistsError()
            email_hash = self.key_to_link[key][ALDictDatabase.KEY_TO_LINK_EMAIL_HASH]
            if email_hash not in self.account:
                raise ALserviceDbKeyDoNotExistsError()
            uuid = self.account[email_hash][ALDictDatabase.ACCOUNT_UUID]
            if uuid is None:
                LOGGER.critical("Could not find a uuid.")
                raise ALserviceDbUnknownError()
            return uuid
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while getting uuid.")
            raise

    def save_ticket_state(self, ticket: str, key: str, idp: str, redirect: str):
        """
        See ALdatabase#save_ticket_state
        """
        try:
            super(ALDictDatabase, self).save_ticket_state(ticket, key, idp, redirect)
            if ticket in self.ticket:
                LOGGER.error("Duplicate tickets (%s) are not allowed!" % ticket)
                raise ALserviceDbNotUniqueTokenError()

            _dict = {
                ALDictDatabase.TICKET_IDP: idp,
                ALDictDatabase.TICKET_KEY: key,
                ALDictDatabase.TICKET_REDIRECT_URL: redirect,
                ALDictDatabase.TICKET_TIMESTAMP: datetime.now()
            }
            self.ticket[ticket] = _dict
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while saving ticket.")
            raise

    def save_token_state(self, token: str, email_hash: str):
        """
        See ALdatabase#save_token_state
        """
        try:
            super(ALDictDatabase, self).save_token_state(token, email_hash)
            if token in self.token:
                LOGGER.error("Duplicate tokens (%s) are not allowed!" % token)
                raise ALserviceDbNotUniqueTokenError()
            _dict = {
                ALDictDatabase.TOKEN_EMAIL_HASH: email_hash,
                ALDictDatabase.TICKET_TIMESTAMP: datetime.now()
            }
            self.token[token] = _dict
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while saving token state.")
            raise

    def get_token_state(self, token: str) -> TokenState:
        """
        See ALdatabase#get_token_state
        """
        try:
            super(ALDictDatabase, self).get_token_state(token)
            if token not in self.token:
                LOGGER.warn("Token (%s) is not in the database." % token)
                raise ALserviceDbKeyDoNotExistsError()
            _dict = self.token[token]
            email_hash = _dict[ALDictDatabase.TOKEN_EMAIL_HASH]
            timestamp = _dict[ALDictDatabase.TOKEN_TIMESTAMP]
            email_state = TokenState(timestamp, email_hash)
            return email_state
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while getting token state.")
            raise

    def get_ticket_state(self, ticket: str) -> TicketState:
        """
        See ALdatabase#get_ticket_state
        """
        try:
            super(ALDictDatabase, self).get_ticket_state(ticket)
            if ticket not in self.ticket:
                LOGGER.warn("Ticket (%s) is not in the database." % ticket)
                raise ALserviceDbKeyDoNotExistsError()
            _dict = self.ticket[ticket]
            key = _dict[ALDictDatabase.TICKET_KEY]
            idp = _dict[ALDictDatabase.TICKET_IDP]
            timestamp = _dict[ALDictDatabase.TICKET_TIMESTAMP]
            redirect = _dict[ALDictDatabase.TICKET_REDIRECT_URL]
            ticket_state = TicketState(timestamp, key, idp, redirect)
            return ticket_state
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while getting ticket state.")
            raise

    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        """
        See ALdatabase#create_account
        """
        try:
            super(ALDictDatabase, self).create_account(email_hash, pin_hash, uuid)
            if email_hash in self.account:
                raise ALserviceDbNotUniqueTokenError()
            _dict_account = {
                ALDictDatabase.ACCOUNT_PIN_HASH: pin_hash,
                ALDictDatabase.ACCOUNT_UUID: uuid,
                ALDictDatabase.ACCOUNT_TIMESTAMP: datetime.now()
            }
            self.account[email_hash] = _dict_account
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                LOGGER.exception("Unkown error while creating account.")
                raise ALserviceDbUnknownError() from error
            raise

    def create_link(self, key: str, idp: str, email_hash: str):
        """
        See ALdatabase#create_link
        """
        try:
            super(ALDictDatabase, self).create_link(key, idp, email_hash)
            link = ALDictDatabase._create_link(email_hash, idp)
            self.remove_link(email_hash, idp)
            if key in self.key_to_link:
                LOGGER.error("Unknown key (%s) in key_to_link." % key)
                raise ALserviceDbNotUniqueTokenError()
            _dict = {
                ALDictDatabase.KEY_TO_LINK_IDP: idp,
                ALDictDatabase.KEY_TO_LINK_EMAIL_HASH: email_hash
            }

            _dict_account_to_link = {
                ALDictDatabase.ACCOUNT_TO_LINK_KEY: key,
                ALDictDatabase.ACCOUNT_TO_LINK_LINK: link,
            }
            if email_hash not in self.account_to_link:
                self.account_to_link[email_hash] = []
            self.account_to_link[email_hash].append(_dict_account_to_link)
            self.key_to_link[key] = _dict
            self.link_to_key[link] = key
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while creating a link.")
            raise

    @staticmethod
    def _create_link(email_hash: str, idp: str):
        link = hashlib.sha512(idp.encode() + email_hash.encode()).hexdigest()
        return link

    def remove_link(self, email_hash: str, idp: str):
        """
        See ALdatabase#remove_link
        """
        try:
            super(ALDictDatabase, self).remove_link(email_hash, idp)
            link = ALDictDatabase._create_link(email_hash, idp)
            if link in self.link_to_key:
                del_key = self.link_to_key[link]
                del self.key_to_link[del_key]
                del self.link_to_key[link]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while removing a link.")
            raise

    def verify_account(self, email_hash: str, pin_hash: str):
        """
        See ALdatabase#verify_account
        """
        try:
            super(ALDictDatabase, self).verify_account(email_hash, pin_hash)
            if email_hash not in self.account:
                raise ALserviceDbKeyDoNotExistsError()
            if pin_hash != self.account[email_hash][ALDictDatabase.ACCOUNT_PIN_HASH]:
                LOGGER.error("Not a correct pin!")
                raise ALserviceDbValueDoNotExistsError()
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while verifying account.")
            raise

    def remove_ticket_state(self, ticket: str):
        """
        See ALdatabase#remove_ticket_state
        """
        try:
            super(ALDictDatabase, self).remove_ticket_state(ticket)
            if ticket in self.ticket:
                del self.ticket[ticket]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while removing ticket state.")
            raise

    def remove_token_state(self, token: str):
        """
        See ALdatabase#remove_token_state
        """
        try:
            super(ALDictDatabase, self).remove_token_state(token)
            if token in self.token:
                del self.token[token]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            LOGGER.exception("Unkown error while removing token state.")
            raise

    def remove_account(self, email_hash: str):
        """
        See ALdatabase#remove_token_account
        """
        try:
            super(ALDictDatabase, self).remove_account(email_hash)
            if email_hash in self.account:
                del self.account[email_hash]
                _dict_account_to_link = self.account_to_link[email_hash]
                for tmp_link in _dict_account_to_link:
                    del self.link_to_key[tmp_link[ALDictDatabase.ACCOUNT_TO_LINK_LINK]]
                    del self.key_to_link[tmp_link[ALDictDatabase.ACCOUNT_TO_LINK_KEY]]
                del self.account_to_link[email_hash]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                LOGGER.exception("Unkown error while removing account.")
                raise ALserviceDbUnknownError() from error
            raise

    def change_pin(self, email_hash: str, old_pin_hash: str, new_pin_hash: str):
        """
        See ALdatabase#create_account
        """
        try:
            super(ALDictDatabase, self).change_pin(email_hash, old_pin_hash, new_pin_hash)
            self.verify_account(email_hash, old_pin_hash)
            self.account[email_hash][ALDictDatabase.ACCOUNT_PIN_HASH] = new_pin_hash
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                LOGGER.exception("Unkown error while changing pin.")
                raise ALserviceDbUnknownError() from error
            raise

    def _get_account_link_data(self, email_hash: str) -> list:
        if email_hash in self.account_to_link:
            return self.account_to_link[email_hash]
        return None


class ALSQLiteDatabase(AccountLinkingDB):
    TICKET_TABLE_NAME = "ticket_table"
    TOKEN_TABLE_NAME = "token_table"
    ACCOUNT_TABLE_NAME = "account_table"
    KEY_TO_LINK_TABLE_NAME = "key_to_link_table"
    LINK_TO_KEY_TABLE_NAME = "link_to_key_table"
    ACCOUNT_TO_LINK_TABLE_NAME = "account_to_link_table"

    def __init__(self, database_path=None):
        self.c_db = dataset.connect('sqlite:///:memory:')
        if database_path:
            self.c_db = dataset.connect('sqlite:///' + database_path)
        self.ticket_table = self.c_db.get_table(
            self.TICKET_TABLE_NAME,
            primary_id=ALDictDatabase.TICKET_TICKET_PRIMARY,
            primary_type='String(250)'
        )
        self.token_table = self.c_db.get_table(
            self.TOKEN_TABLE_NAME,
            primary_id=ALDictDatabase.TOKEN_TOKEN_PRIMARY,
            primary_type='String(250)'
        )
        self.account_table = self.c_db.get_table(
            self.ACCOUNT_TABLE_NAME,
            primary_id=ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY,
            primary_type='String(250)'
        )
        self.key_to_link_table = self.c_db.get_table(
            self.KEY_TO_LINK_TABLE_NAME,
            primary_id=ALDictDatabase.KEY_TO_LINK_KEY_PRIMARY,
            primary_type='String(250)'
        )
        self.link_to_key_table = self.c_db.get_table(
            self.LINK_TO_KEY_TABLE_NAME,
            primary_id=ALDictDatabase.LINK_TO_KEY_LINK_PRIMARY,
            primary_type='String(250)'
        )
        self.account_to_link_table = self.c_db.get_table(
            self.ACCOUNT_TO_LINK_TABLE_NAME,
            primary_id=ALDictDatabase.ACCOUNT_TO_LINK_EMAIL_HASH_PRIMARY,
            primary_type='String(250)'
        )

    def get_uuid(self, key: str) -> str:
        """
        See ALdatabase#get_uuid
        """
        try:
            super(ALSQLiteDatabase, self).get_uuid(key)

            if not self.key_to_link_table.find_one(key=key):
                raise ALserviceDbKeyDoNotExistsError()

            row = self.key_to_link_table.find_one(key=key)

            try:
                email_hash = row[ALDictDatabase.KEY_TO_LINK_EMAIL_HASH]
            except KeyError:
                email_hash = None

            account = self.account_table.find_one(email=email_hash)
            if not account:
                raise ALserviceDbKeyDoNotExistsError()

            uuid = account[ALDictDatabase.ACCOUNT_UUID]

            if uuid is None:
                raise ALserviceDbUnknownError()
            return uuid
        except Exception as error:
            self.handle_exception(error)

    def handle_exception(self, error):
        if not isinstance(error, ALserviceDbError):
            raise ALserviceDbUnknownError() from error
        LOGGER.exception("Unkown error while getting uuid.")
        raise

    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        """
        See ALdatabase#create_account
        """
        try:
            super(ALSQLiteDatabase, self).create_account(email_hash, pin_hash, uuid)
            if self.account_table.find_one(email=email_hash):
                raise ALserviceDbNotUniqueTokenError()
            _dict_account = {
                ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY: email_hash,
                ALDictDatabase.ACCOUNT_PIN_HASH: pin_hash,
                ALDictDatabase.ACCOUNT_UUID: uuid,
                ALDictDatabase.ACCOUNT_TIMESTAMP: str(datetime.now())
            }
            self.account_table.insert(_dict_account)
        except Exception as error:
            self.handle_exception(error)

    def _create_link(self, email_hash: str, idp: str):
        link = hashlib.sha512(idp.encode() + email_hash.encode()).hexdigest()
        return link

    def create_link(self, key: str, idp: str, email_hash: str):
        try:
            super(ALSQLiteDatabase, self).create_link(key, idp, email_hash)
            link = ALDictDatabase._create_link(email_hash, idp)
            self.remove_link(email_hash, idp)
            # if self.key_to_link_table.find_one(key=key):
            _dict_key_to_link = {
                ALDictDatabase.KEY_TO_LINK_KEY_PRIMARY: key,
                ALDictDatabase.KEY_TO_LINK_IDP: idp,
                ALDictDatabase.KEY_TO_LINK_EMAIL_HASH: email_hash
            }

            _account_to_link_data = {
                ALDictDatabase.ACCOUNT_TO_LINK_KEY: key,
                ALDictDatabase.ACCOUNT_TO_LINK_LINK: link,
            }

            _dict_account_to_link = {
                ALDictDatabase.ACCOUNT_TO_LINK_EMAIL_HASH_PRIMARY: email_hash,
                "data": json.dumps([_account_to_link_data])
            }

            _dict_link_to_key = {
                ALDictDatabase.LINK_TO_KEY_LINK_PRIMARY: link,
                ALDictDatabase.LINK_TO_KEY_KEY: key
            }

            try:
                result = self.account_to_link_table.find_one(email=email_hash)
                if result:
                    account_list = json.loads(result["data"])
                    account_list.append(_account_to_link_data)
                    _dict_account_to_link['data'] = json.dumps(account_list)
                self.account_to_link_table.upsert(
                    _dict_account_to_link,
                    [ALDictDatabase.ACCOUNT_TO_LINK_EMAIL_HASH_PRIMARY]
                )
                self.key_to_link_table.insert(_dict_key_to_link)
                self.link_to_key_table.insert(_dict_link_to_key)
            except IntegrityError as err:
                raise ALserviceDbNotUniqueTokenError()
        except Exception as error:
            self.handle_exception(error)

    def remove_link(self, email_hash: str, idp: str):
        try:
            super(ALSQLiteDatabase, self).remove_link(email_hash, idp)
            link = ALDictDatabase._create_link(email_hash, idp)
            result = self.link_to_key_table.find_one(link=link)
            if result:
                key = result[ALDictDatabase.KEY_TO_LINK_KEY_PRIMARY]
                self.key_to_link_table.delete(key=key)
                self.link_to_key_table.delete(link=link)
        except Exception as error:
            self.handle_exception(error)

    def get_ticket_state(self, result: str) -> TicketState:
        try:
            super(ALSQLiteDatabase, self).get_ticket_state(result)
            result = self.ticket_table.find_one(ticket=result)
            if not result:
                raise ALserviceDbKeyDoNotExistsError()
            key = result[ALDictDatabase.TICKET_KEY]
            idp = result[ALDictDatabase.TICKET_IDP]
            timestamp = result[ALDictDatabase.TICKET_TIMESTAMP]
            redirect = result[ALDictDatabase.TICKET_REDIRECT_URL]
            ticket_state = TicketState(timestamp, key, idp, redirect)
            return ticket_state
        except Exception as error:
            self.handle_exception(error)

    def save_ticket_state(self, ticket: str, key: str, idp: str, redirect: str):
        try:
            super(ALSQLiteDatabase, self).save_ticket_state(ticket, key, idp, redirect)
            if self.ticket_table.find_one(ticket=ticket):
                raise ALserviceDbNotUniqueTokenError()
            _dict = {
                ALDictDatabase.TICKET_TICKET_PRIMARY: ticket,
                ALDictDatabase.TICKET_IDP: idp,
                ALDictDatabase.TICKET_KEY: key,
                ALDictDatabase.TICKET_REDIRECT_URL: redirect,
                ALDictDatabase.TICKET_TIMESTAMP: datetime.now()
            }
            self.ticket_table.insert(_dict)
        except Exception as error:
            self.handle_exception(error)

    def save_token_state(self, token: str, email_hash: str):
        try:
            super(ALSQLiteDatabase, self).save_token_state(token, email_hash)
            if self.token_table.find_one(token=token):
                raise ALserviceDbNotUniqueTokenError()
            _dict = {
                ALDictDatabase.TOKEN_TOKEN_PRIMARY: token,
                ALDictDatabase.TOKEN_EMAIL_HASH: email_hash,
                ALDictDatabase.TICKET_TIMESTAMP: datetime.now()
            }
            self.token_table.insert(_dict)
        except Exception as error:
            self.handle_exception(error)

    def get_token_state(self, token: str) -> TokenState:
        try:
            super(ALSQLiteDatabase, self).get_token_state(token)
            result = self.token_table.find_one(token=token)
            if not result:
                raise ALserviceDbKeyDoNotExistsError()
            email_hash = result[ALDictDatabase.TOKEN_EMAIL_HASH]
            timestamp = result[ALDictDatabase.TOKEN_TIMESTAMP]
            email_state = TokenState(timestamp, email_hash)
            return email_state
        except Exception as error:
            self.handle_exception(error)

    def verify_account(self, email_hash: str, pin_hash: str):
        try:
            super(ALSQLiteDatabase, self).verify_account(email_hash, pin_hash)
            account = self.account_table.find_one(email=email_hash)
            if not account:
                raise ALserviceDbKeyDoNotExistsError()
            if pin_hash != account[ALDictDatabase.ACCOUNT_PIN_HASH]:
                raise ALserviceDbValueDoNotExistsError()
        except Exception as error:
            self.handle_exception(error)

    def remove_ticket_state(self, ticket: str):
        try:
            super(ALSQLiteDatabase, self).remove_ticket_state(ticket)
            self.ticket_table.delete(ticket=ticket)
        except Exception as error:
            self.handle_exception(error)

    def remove_token_state(self, token: str):
        try:
            super(ALSQLiteDatabase, self).remove_token_state(token)
            self.token_table.delete(token=token)
        except Exception as error:
            self.handle_exception(error)

    def remove_account(self, email_hash: str):
        try:
            super(ALSQLiteDatabase, self).remove_account(email_hash)
            self.account_table.delete(email=email_hash)
            _dict_account_to_link = self.account_to_link_table.find_one(email=email_hash)
            if _dict_account_to_link:
                account_to_link_list = json.loads(_dict_account_to_link['data'])
                for tmp_link in account_to_link_list:
                    self.link_to_key_table.delete(link=tmp_link[ALDictDatabase.ACCOUNT_TO_LINK_LINK])
                    self.key_to_link_table.delete(key=tmp_link[ALDictDatabase.ACCOUNT_TO_LINK_KEY])
                self.account_to_link_table.delete(email=email_hash)
        except Exception as error:
            self.handle_exception(error)

    def _get_account_link_data(self, email_hash: str) -> list:
        result = self.account_to_link_table.find_one(email=email_hash)
        if result:
            return json.loads(result['data'])
        return None

    def change_pin(self, email_hash: str, old_pin_hash: str, new_pin_hash: str):
        try:
            super(ALSQLiteDatabase, self).change_pin(email_hash, old_pin_hash, new_pin_hash)
            self.verify_account(email_hash, old_pin_hash)
            row = self.account_table.find_one(email=email_hash)
            row[ALDictDatabase.ACCOUNT_PIN_HASH] = new_pin_hash
            self.account_table.upsert(row, [ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY])
        except Exception as error:
            self.handle_exception(error)
