__author__ = 'haho0032'


class TicketState(object):

    def __init__(self, timestamp, key, idp):
        """

        :timestamp datetime
        :jwt: dict

        :param timestamp:
        :param data:
        :return:
        """
        self.key = key
        self.idp = idp


class EmailState(object):

    def __init__(self, timestamp, email_hash, pin=None):
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

    def get_uuid(self, key: str) -> str:
        """

        :param key: A key that uniquely identifies an Idp and the users identification on that IdP.
        :return: An accounts uuid.
        """
        raise NotImplementedError()

    # save_uuid_request create timestamp in function/db
    def save_ticket_state(self, ticket: str, key: str, idp: str):
        """
        :param ticket: A uuid that represents a state.
        :param state: The state
        :return:
        """
        raise NotImplementedError()

    #save_email (saving token for email) Create timestamp in function
    def save_token_state(self, token: str, email_hash: str):
        """

        :param token: A uuid that represents a state.
        :param state: The state
        :return:
        """
        raise NotImplementedError()

    #get_email
    def get_token_state(self, token: str) -> EmailState:
        """

        :param token:
        :return:
        """
        raise NotImplementedError()

    #get_uuid_request
    def get_ticket_state(self, ticket: str) -> TicketState:
        raise NotImplementedError()

    #save_email (saves account information) create timestamp in function/db
    def create_account(self, email_hash: str, pin_hash: str, uuid: str):
        raise NotImplementedError

    #save_uuid
    def create_link(self, key: str, idp: str, email_hash: str):
        NotImplementedError()

    #get_user_uuid
    def verify_account(self, email_hash: str, pin_hash: str) -> str:
        NotImplementedError()

    def remove_ticket_state(self, ticket: str):
        NotImplementedError()

    def remove_token_state(self, token: str):
        NotImplementedError()


class ALDictDatabase(ALdatabase):
    TICKET_TICKET_PRIMARY = "ticket"
    TICKET_TIMESTAMP = "timestamp"
    TICKET_KEY = "key"
    TICKET_IDP = "idp"

    TOKEN_TOKEN_PRIMARY = "token"
    TOKEN_TIMESTAMP = "timestamp"
    TOKEN_EMAIL_HASH = "email"

    ACCOUNT_EMAIL_HASH_PRIMARY = "email"
    ACCOUNT_UUID = "uuid"
    ACCOUNT_PIN_HASH = "pin"
    ACCOUNT_TIMESTAMP = "timestamp"

    KEY_TO_LINK_KEY_PRIMARY = "key"
    KEY_TO_LINK_IDP = "idp"
    KEY_TO_LINK_EMAIL_HASH ="email"

    #lik = hash(idp + email)
    LINK_TO_KEY_LINK_PRIMARY = "link"
    LINK_TO_KEY_KEY = "key"

    def __init__(self):
        self.ticket = {}
        self.token = {}
        self.account = {}
        self.key_to_link = {}
        self.link_to_key = {}

    def _remove_key(self, idp: str, email_hash: str):
        NotImplementedError()