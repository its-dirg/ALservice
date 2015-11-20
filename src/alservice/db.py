from abc import abstractmethod
from datetime import datetime
import hashlib

from alservice.exception import ALserviceDbKeyDoNotExistsError, ALserviceDbUnknownError, \
    ALserviceDbNotUniqueTokenError, ALserviceDbValidationError, ALserviceDbValueDoNotExistsError, \
    ALserviceDbError


class TicketState(object):
    def __init__(self, timestamp: datetime, key, idp, redirect):
        """

        :timestamp datetime
        :jwt: dict

        :param timestamp:
        :param data:
        :return:
        """
        self.timestamp = timestamp
        self.key = key
        self.idp = idp
        self.redirect = redirect


class TokenState(object):
    def __init__(self, timestamp, email_hash):
        """

        :timestamp datetime
        :jwt: dict

        :param timestamp:
        :param data:
        :return:
        """
        self.timestamp = timestamp
        self.email_hash = email_hash


class ALdatabase(object):

    @staticmethod
    def validation(attributes: dict):
        validation_message = ""
        if attributes is not None:
            for attr in attributes:
                if attributes[attr] is None:
                    validation_message += "The value for %s is not allowed to be empty." % attr
                elif not isinstance(attributes[attr], str):
                    validation_message += "The type of %s must be string." % attr
        if len(validation_message) > 0:
            raise ALserviceDbValidationError(validation_message)

    @abstractmethod
    def get_uuid(self, key: str) -> str:
        """

        :param key: A key that uniquely identifies an Idp and the users identification on that IdP.
        :return: An accounts uuid.
        """
        return None

    @abstractmethod
    def save_ticket_state(self, ticket: str, key: str, idp: str, redirect: str):
        """
        :param ticket: A uuid that represents a state.
        :param state: The state
        :return:
        """
        return

    @abstractmethod
    def save_token_state(self, token: str, email_hash: str):
        """

        :param token: A uuid that represents a state.
        :param state: The state
        :return:
        """
        return

    @abstractmethod
    def get_token_state(self, token: str) -> TokenState:
        """

        :param token:
        :return:
        """
        return None

    @abstractmethod
    def get_ticket_state(self, ticket: str) -> TicketState:
        return None

    @abstractmethod
    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        return

    @abstractmethod
    def create_link(self, key: str, idp: str, email_hash: str):
        return

    @abstractmethod
    def remove_link(self, email_hash: str, idp: str):
        return None

    @abstractmethod
    def verify_account(self, email_hash: str, pin_hash: str):
        return None

    @abstractmethod
    def remove_ticket_state(self, ticket: str):
        return

    @abstractmethod
    def remove_token_state(self, token: str):
        return

    @abstractmethod
    def remove_account(self, email_hash: str):
        return

    @abstractmethod
    def change_pin(self, email_hash: str, old_pin_hash: str, new_pin_hash: str):
        return

    @abstractmethod
    def db_empty(self) -> bool:
        return

    @abstractmethod
    def db_clear(self):
        return


class ALDictDatabase(ALdatabase):
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
        """:type: dict[str, dict[str, str]]"""

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
            ALDictDatabase.validation(
                {
                    ALDictDatabase.KEY_TO_LINK_KEY_PRIMARY: key
                }
            )
            if key not in self.key_to_link:
                raise ALserviceDbKeyDoNotExistsError()
            email_hash = self.key_to_link[key][ALDictDatabase.KEY_TO_LINK_EMAIL_HASH]
            if email_hash not in self.account:
                raise ALserviceDbKeyDoNotExistsError()
            uuid = self.account[email_hash][ALDictDatabase.ACCOUNT_UUID]
            if uuid is None:
                raise ALserviceDbUnknownError()
            return uuid
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def save_ticket_state(self, ticket: str, key: str, idp: str, redirect: str):
        """
        See ALdatabase#save_ticket_state
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.TICKET_TICKET_PRIMARY: ticket,
                    ALDictDatabase.TICKET_KEY: key,
                    ALDictDatabase.TICKET_IDP: idp,
                    ALDictDatabase.TICKET_REDIRECT_URL: redirect,
                }
            )
            if ticket in self.ticket:
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
            raise

    def save_token_state(self, token: str, email_hash: str):
        """
        See ALdatabase#save_token_state
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.TOKEN_TOKEN_PRIMARY: token,
                    ALDictDatabase.TOKEN_EMAIL_HASH: email_hash
                }
            )
            if token in self.token:
                raise ALserviceDbNotUniqueTokenError()
            _dict = {
                ALDictDatabase.TOKEN_EMAIL_HASH: email_hash,
                ALDictDatabase.TICKET_TIMESTAMP: datetime.now()
            }
            self.token[token] = _dict
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def get_token_state(self, token: str) -> TokenState:
        """
        See ALdatabase#get_token_state
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.TOKEN_TOKEN_PRIMARY: token
                }
            )
            if token not in self.token:
                raise ALserviceDbKeyDoNotExistsError()
            _dict = self.token[token]
            email_hash = _dict[ALDictDatabase.TOKEN_EMAIL_HASH]
            timestamp = _dict[ALDictDatabase.TOKEN_TIMESTAMP]
            email_state = TokenState(timestamp, email_hash)
            return email_state
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def get_ticket_state(self, ticket: str) -> TicketState:
        """
        See ALdatabase#get_ticket_state
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.TICKET_TICKET_PRIMARY: ticket
                }
            )
            if ticket not in self.ticket:
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
            raise

    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        """
        See ALdatabase#create_account
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY: email_hash,
                    ALDictDatabase.ACCOUNT_PIN_HASH: pin_hash,
                    ALDictDatabase.ACCOUNT_UUID: uuid
                }
            )
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
                raise ALserviceDbUnknownError() from error
            raise

    def create_link(self, key: str, idp: str, email_hash: str):
        """
        See ALdatabase#create_link
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.KEY_TO_LINK_KEY_PRIMARY: key,
                    ALDictDatabase.KEY_TO_LINK_IDP: idp,
                    ALDictDatabase.KEY_TO_LINK_EMAIL_HASH: email_hash
                }
            )
            link = self._create_link(email_hash, idp)
            self.remove_link(email_hash, idp)
            if key in self.key_to_link:
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
            raise

    def _create_link(self, email_hash: str, idp: str):
        link = hashlib.sha512(idp.encode() + email_hash.encode()).hexdigest()
        return link

    def remove_link(self, email_hash: str, idp: str):
        """
        See ALdatabase#remove_link
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.KEY_TO_LINK_IDP: idp,
                    ALDictDatabase.KEY_TO_LINK_EMAIL_HASH: email_hash
                }
            )
            link = self._create_link(email_hash, idp)
            if link in self.link_to_key:
                del_key = self.link_to_key[link]
                del self.key_to_link[del_key]
                del self.link_to_key[link]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def verify_account(self, email_hash: str, pin_hash: str):
        """
        See ALdatabase#verify_account
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY: email_hash,
                    ALDictDatabase.ACCOUNT_PIN_HASH: pin_hash
                }
            )
            if email_hash not in self.account:
                raise ALserviceDbKeyDoNotExistsError()
            if pin_hash != self.account[ALDictDatabase.ACCOUNT_PIN_HASH]:
                raise ALserviceDbValueDoNotExistsError()
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def remove_ticket_state(self, ticket: str):
        """
        See ALdatabase#remove_ticket_state
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.TICKET_TICKET_PRIMARY: ticket
                }
            )
            if ticket in self.ticket:
                del self.ticket[ticket]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def remove_token_state(self, token: str):
        """
        See ALdatabase#remove_token_state
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.TOKEN_TOKEN_PRIMARY: token
                }
            )
            if token in self.token:
                del self.token[token]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def remove_account(self, email_hash: str):
        """
        See ALdatabase#remove_token_account
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY: email_hash
                }
            )
            if email_hash in self.account:
                del self.account[email_hash]
                _dict_account_to_link = self.account_to_link[email_hash]
                for tmp_link in _dict_account_to_link:
                    del self.link_to_key[tmp_link[ALDictDatabase.ACCOUNT_TO_LINK_LINK]]
                    del self.key_to_link[tmp_link[ALDictDatabase.ACCOUNT_TO_LINK_LINK]]
                del self.account_to_link[email_hash]
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def change_pin(self, email_hash: str, old_pin_hash: str, new_pin_hash: str):
        """
        See ALdatabase#create_account
        """
        try:
            ALDictDatabase.validation(
                {
                    ALDictDatabase.ACCOUNT_EMAIL_HASH_PRIMARY: email_hash,
                    ALDictDatabase.ACCOUNT_PIN_HASH: old_pin_hash,
                }
            )
            ALDictDatabase.validation(
                {
                    ALDictDatabase.ACCOUNT_PIN_HASH: new_pin_hash,
                }
            )
            self.verify_account(email_hash, old_pin_hash)
            self.account[email_hash][ALDictDatabase.ACCOUNT_PIN_HASH] = new_pin_hash
        except Exception as error:
            if not isinstance(error, ALserviceDbError):
                raise ALserviceDbUnknownError() from error
            raise

    def db_empty(self) -> bool:
        """
        See ALdatabase#db_empty
        """

        return ((len(self.ticket) + len(self.token) + len(self.account) + len(self.key_to_link) +
                 len(self.link_to_key) + len(self.account_to_link)) == 0)

    def db_clear(self):
        """
        See ALdatabase#db_clear
        """

        self.ticket = {}
        self.token = {}
        self.account = {}
        self.key_to_link = {}
        self.link_to_key = {}
        self.account_to_link = {}
