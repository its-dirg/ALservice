from unittest.mock import MagicMock, Mock
import pytest
from alservice.al import AccountLinking, Email, JWTHandler
from alservice.db import ALdatabase, ALDictDatabase
from alservice.exception import ALserviceDbKeyDoNotExistsError, ALserviceTicketError, \
    ALserviceTokenError, ALserviceAccountExists, ALserviceAuthenticationError, ALserviceNoSuchKey


class TestEmail(Email):

    def __init__(self):
        self.token = None
        self.email_to = None

    def send_mail(self, token: str, email_to: str):
        self.token = token
        self.email_to = email_to


class TestAL(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        self.my_idp = "my_idp"
        jso = {
            "id": "my_id",
            "idp": self.my_idp
        }
        self.my_key = JWTHandler.key(jso)
        self.db = ALDictDatabase()
        self.al = AccountLinking(db=self.db,
                                 salt="my_salt",
                                 email_sender_create_account=TestEmail(),
                                 email_sender_pin_recovery=TestEmail())

    @pytest.mark.parametrize("pin", ["", "1234", "ALiteBitHarder#2"])
    def test_create_account_flow(self, pin):
        _error = None
        try:
            self.al.get_uuid(self.my_key)
        except ALserviceNoSuchKey as error:
            _error = error
        assert _error is not None
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        _error = None
        try:
            self.al.create_account_step1("my_email", "incorrect_ticket")
        except ALserviceTicketError as error:
            _error = error
        assert _error is not None
        self.al.create_account_step1("my_email", ticket)
        assert self.al.email_sender_create_account.email_to == "my_email"
        assert self.al.email_sender_create_account.token is not None
        token = self.al.email_sender_create_account.token
        _error = None
        try:
            self.al.create_account_step2("incorrect_token")
        except ALserviceTokenError as error:
            _error = error
        assert _error is not None
        _error = None
        try:
            self.al.create_account_step2("incorrect_token.incorrect_ticken")
        except ALserviceTicketError as error:
            _error = error
        assert _error is not None
        _error = None
        try:
            test_token = "%s.%s" % ("incorrect_token", ticket)
            self.al.create_account_step2(test_token)
        except ALserviceTokenError as error:
            _error = error
        assert _error is not None
        token_test = self.al.create_account_step2(token)
        assert token == token_test
        _error = None
        try:
            self.al.create_account_step3("incorrect_token", pin)
        except ALserviceTokenError as error:
            _error = error
        assert _error is not None
        try:
            self.al.create_account_step3("incorrect_token.incorrect_ticket", pin)
        except ALserviceTokenError as error:
            _error = error
        assert _error is not None
        try:
            test_token = "%s.%s" % (token.split(".")[0], "incorrect_ticket")
            self.al.create_account_step3(test_token, pin)
        except ALserviceTicketError as error:
            _error = error
        self.al.create_account_step3(token, pin)
        uuid_1 = self.al.get_uuid(self.my_key)
        uuid_2 = self.al.get_uuid(self.my_key)
        assert uuid_1 == uuid_2

    @pytest.mark.parametrize("pin", ["", "1234", "ALiteBitHarder#2"])
    def test_change_account_linking(self, pin):
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)
        self.al.create_account_step3(token, pin)
        uuid_1 = self.al.get_uuid(self.my_key)
        uuid_2 = self.al.get_uuid(self.my_key)
        assert uuid_1 == uuid_2
        assert uuid_1 == uuid_2
        ticket = self.al.create_ticket("my_new_key", self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)
        _error = None
        try:
            self.al.create_account_step3(token, pin)
        except ALserviceAccountExists as error:
            _error = error
        assert _error is not None
        ticket = self.al.create_ticket("my_new_key", self.my_idp, "my_redirect")
        _error = None
        try:
            self.al.link_key("my_email", "wrong_pin", ticket)
        except ALserviceAuthenticationError as error:
            _error = error
        assert _error is not None
        _error = None
        try:
            self.al.link_key("_wrong_my_email", pin, ticket)
        except ALserviceAuthenticationError as error:
            _error = error
        assert _error is not None

        self.al.link_key("my_email", pin, ticket)
        uuid_1 = self.al.get_uuid("my_new_key")
        uuid_2 = self.al.get_uuid("my_new_key")
        assert uuid_1 == uuid_2
        _error = None
        try:
            self.al.get_uuid(self.my_key)
        except ALserviceNoSuchKey as error:
            _error = error
        assert _error is not None

    @pytest.mark.parametrize("pin", ["", "1234", "ALiteBitHarder#2"])
    def test_duplicate_key(self, pin):
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)
        self.al.create_account_step3(token, pin)
        uuid_1 = self.al.get_uuid(self.my_key)
        uuid_2 = self.al.get_uuid(self.my_key)
        assert uuid_1 == uuid_2
        assert uuid_1 == uuid_2
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email_2", ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)
        _error = None
        try:
            self.al.create_account_step3(token, pin)
        except ALserviceAccountExists as error:
            _error = error
        assert _error is not None

    def test_multipleusers_keys(self):
        for i in range(0, 1000):
            my_pin = "my_pin321423432###_%i" % i
            my_idp = "my_idp_%i" % i
            my_email = "my_email_%i" % i
            my_id = "my_id_%i" % i
            jso = {
                "id": my_id,
                "idp": my_idp
            }
            my_key = JWTHandler.key(jso)
            ticket = self.al.create_ticket(my_key, my_idp, "my_redirect")
            self.al.create_account_step1(my_email, ticket)
            token = self.al.email_sender_create_account.token
            token = self.al.create_account_step2(token)
            self.al.create_account_step3(token, my_pin)
            uuid_1 = self.al.get_uuid(my_key)
            uuid_2 = self.al.get_uuid(my_key)
            assert uuid_1 == uuid_2
            for i in range(0, 10):
                my_id_tmp = "%s_%i" % (my_id, i)
                my_idp_tmp = "%s_%i" % (my_idp, i)
                jso = {
                    "id": my_id_tmp,
                    "idp": my_idp_tmp
                }
                my_key_tmp = JWTHandler.key(jso)
                ticket = self.al.create_ticket(my_key_tmp, my_idp_tmp, "my_redirect")
                self.al.link_key(my_email, my_pin, ticket)
                uuid_1_tmp = self.al.get_uuid(my_key_tmp)
                assert uuid_1 == uuid_1_tmp
        uuid_dict = {}
        for i in range(0, 1000):
            my_idp = "my_idp_%i" % i
            my_id = "my_id_%i" % i
            jso = {
                "id": my_id,
                "idp": my_idp
            }
            my_key = JWTHandler.key(jso)
            uuid_1 = self.al.get_uuid(my_key)
            uuid_2 = self.al.get_uuid(my_key)
            assert uuid_1 == uuid_2
            assert uuid_1 not in uuid_dict
            uuid_dict[uuid_1] = True
            for i in range(0, 10):
                my_id_tmp = "%s_%i" % (my_id, i)
                my_idp_tmp = "%s_%i" % (my_idp, i)
                jso = {
                 "id": my_id_tmp,
                 "idp": my_idp_tmp
                }
                my_key_tmp = JWTHandler.key(jso)
                uuid_1_tmp = self.al.get_uuid(my_key_tmp)
                assert uuid_1 == uuid_1_tmp

    def change_pin(self):
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)
        self.al.create_account_step3(token, "4534j5khtfdgkjhgkjdfsh#")
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        _error = None
        try:
            self.al.change_pin_step1("my_email_wrong", "4534j5khtfdgkjhgkjdfsh#")
        except ALserviceAuthenticationError as error:
            _error = error
        assert _error is not None
        _error = None
        try:
            self.al.change_pin_step1("my_email", "4534j5khtfdgkjhgkjdfsh#_wrong")
        except ALserviceAuthenticationError as error:
            _error = error
        assert _error is not None
        self.al.change_pin_step1("my_email", "4534j5khtfdgkjhgkjdfsh#")
        token = self.al.email_sender_pin_recovery.token
        try:
            self.al.change_pin_step2(token, "4534j5khtfdgkjhgkjdfsh#_wrong", "my_new_pin123123#!")
        except ALserviceAuthenticationError as error:
            _error = error
        assert _error is not None
        try:
            self.al.change_pin_step2("invalid_token", "4534j5khtfdgkjhgkjdfsh#", "my_new_pin123123#!")
        except ALserviceTokenError as error:
            _error = error
        assert _error is not None
        self.al.change_pin_step2(token, "4534j5khtfdgkjhgkjdfsh#", "my_new_pin123123#!")
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.link_key("my_email", "my_new_pin123123#!", ticket)
        uuid_1 = self.al.get_uuid("my_new_key")
        uuid_2 = self.al.get_uuid("my_new_key")
        assert uuid_1 == uuid_2
