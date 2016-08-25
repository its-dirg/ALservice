import pytest

from alservice.al import AccountLinking, Email, JWTHandler
from alservice.db import ALDictDatabase
from alservice.exception import ALserviceTicketError, \
    ALserviceTokenError, ALserviceAccountExists, ALserviceAuthenticationError, ALserviceNoSuchKey, \
    ALserviceNotAValidPin


class EmailFake(Email):
    def __init__(self):
        self.token = None
        self.email_to = None

    def send_mail(self, token: str, email_to: str):
        self.token = token
        self.email_to = email_to


class TestAL(object):
    def create_account(self, pin, email="my_email", key=None, idp=None):
        ticket = self.al.create_ticket(key or self.my_key, idp or self.my_idp, "my_redirect")
        self.al.create_account_step1(email, ticket)
        assert self.al.email_sender_create_account.email_to == email
        assert self.al.email_sender_create_account.token is not None
        token = self.al.email_sender_create_account.token

        verified_token = self.al.create_account_step2(token)
        assert verified_token == token
        self.al.create_account_step3(token, pin)

    @pytest.fixture(autouse=True)
    def setup(self):
        self.my_idp = "my_idp"
        jso = {
            "id": "my_id",
            "idp": self.my_idp
        }
        self.my_key = JWTHandler.key(jso)
        self.db = ALDictDatabase()
        self.al = AccountLinking(
            trusted_keys=[],
            db=self.db,
            salt="my_salt",
            email_sender_create_account=EmailFake(),
            email_sender_pin_recovery=EmailFake(),
            pin_verify="((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})",
            pin_empty=True)

    def test_get_uuid_should_raise_key_exception_for_unknown_key(self):
        with pytest.raises(ALserviceNoSuchKey):
            self.al.get_uuid("unknown")

    def test_create_account_step1_should_raise_ticket_exception_for_unknown_ticket(self):
        with pytest.raises(ALserviceTicketError):
            self.al.create_account_step1("my_email", "unknown")

    def test_create_account_step2_should_raise_token_exception_for_unknown_token(self):
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step2("unknown")

    def test_create_account_step2_should_raise_ticket_exception_for_unknown_token_and_unknown_ticket(self):
        with pytest.raises(ALserviceTicketError):
            self.al.create_account_step2("unknown_token.unknown_ticket")

    def test_create_account_step2_should_raise_token_exception_for_unknown_token_and_known_ticket(self):
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step2("unknown_token.{}".format(ticket))

    def test_create_account_step3_should_raise_token_exception_for_unknown_token(self):
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step3("incorrect_token", "")

    def test_create_account_step3_should_raise_token_exception_for_unknown_token_and_unknown_ticket(self):
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step3("incorrect_token.incorrect_ticket", "")

    def test_create_account_step3_should_raise_ticket_exception_for_unknown_token_and_known_ticket(self):
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        verified_token = self.al.create_account_step2(token)
        broken_token = "{}.unknown_ticket".format(verified_token.split(".")[0], "incorrect_ticket")
        with pytest.raises(ALserviceTicketError):
            self.al.create_account_step3(broken_token, "")

    @pytest.mark.parametrize("pin", ["", "#NotSoEasy1", "ALiteBitHarder#2!435345#fdgdfg"])
    def test_create_account_flow(self, pin):
        self.create_account(pin)

        uuid_1 = self.al.get_uuid(self.my_key)
        uuid_2 = self.al.get_uuid(self.my_key)
        assert uuid_1 == uuid_2

    def test_create_account_step3_should_raise_exception_if_account_already_exists(self):
        pin = ""
        self.create_account(pin)

        ticket = self.al.create_ticket("my_new_key", self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)

        with pytest.raises(ALserviceAccountExists):
            self.al.create_account_step3(token, pin)

    def test_link_key_should_raise_exception_if_wrong_pin_is_used(self):
        pin = ""
        self.create_account(pin)

        ticket = self.al.create_ticket("my_new_key", self.my_idp, "my_redirect")
        with pytest.raises(ALserviceAuthenticationError):
            self.al.link_key("my_email", "wrong_pin", ticket)

    def test_link_key_should_raise_exception_if_wrong_email_is_used(self):
        pin = ""
        self.create_account(pin)

        ticket = self.al.create_ticket("my_new_key", self.my_idp, "my_redirect")
        with pytest.raises(ALserviceAuthenticationError):
            self.al.link_key("_wrong_my_email", pin, ticket)

    @pytest.mark.parametrize("pin", ["", "#NotSoEasy1", "ALiteBitHarder#2!435345#fdgdfg"])
    def test_change_account_linking(self, pin):
        self.create_account(pin)

        ticket = self.al.create_ticket("my_new_key", self.my_idp, "my_redirect")
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        self.al.create_account_step2(token)

        self.al.link_key("my_email", pin, ticket)
        uuid_1 = self.al.get_uuid("my_new_key")
        uuid_2 = self.al.get_uuid("my_new_key")
        assert uuid_1 == uuid_2

        # the old key has been removed
        with pytest.raises(ALserviceNoSuchKey):
            self.al.get_uuid(self.my_key)

    def test_change_pin_step1_should_raise_exception_for_unknown_email(self):
        pin = "asdkhAas3#"
        self.create_account(pin)
        with pytest.raises(ALserviceAuthenticationError):
            self.al.change_pin_step1("unknown", pin)

    def test_change_pin_step1_should_raise_exception_for_wrong_pin(self):
        pin = "asdkhAas3#"
        email = "test@example.com"
        self.create_account(pin, email)
        with pytest.raises(ALserviceAuthenticationError):
            self.al.change_pin_step1(email, pin + "_wrong")

    def test_change_pin_step2_should_raise_exception_for_wrong_old_pin(self):
        pin = "asdkhAas3#"
        email = "test@example.com"
        self.create_account(pin, email)
        self.al.change_pin_step1(email, pin)
        token = self.al.email_sender_pin_recovery.token

        with pytest.raises(ALserviceAuthenticationError):
            self.al.change_pin_step2(token, pin + "_wrong", "my_new_pin123123#!")

    def test_change_pin_step2_should_raise_exception_for_unknown_token(self):
        pin = "asdkhAas3#"
        email = "test@example.com"
        self.create_account(pin, email)
        self.al.change_pin_step1(email, pin)

        with pytest.raises(ALserviceAuthenticationError):
            self.al.change_pin_step2("unknown", pin, "4534j5khtAAfdgkjhgkjdfsh#")

    def test_change_pin(self):
        pin = "#A4534j5khtfdgkjhgkjdfsh#"
        self.create_account(pin)

        self.al.change_pin_step1("my_email", pin)
        token = self.al.email_sender_pin_recovery.token
        new_pin = "my_new_piAAn123123#!"
        self.al.change_pin_step2(token, pin, new_pin)
        ticket = self.al.create_ticket(self.my_key, self.my_idp, "my_redirect")
        self.al.link_key("my_email", new_pin, ticket)
        uuid_1 = self.al.get_uuid(self.my_key)
        uuid_2 = self.al.get_uuid(self.my_key)
        assert uuid_1 == uuid_2

    @pytest.mark.parametrize("invalid_pin", [
        None,
        "NotOK",
    ])
    def test_verify_pin_should_raise_exception_for_invalid_pin(self, invalid_pin):
        with pytest.raises(ALserviceNotAValidPin):
            self.al.verify_pin(invalid_pin)

    @pytest.mark.parametrize("valid_pin", [
        "aP1n##",
        ""
    ])
    def test_verify_pin(self, valid_pin):
        # should not raise an exception
        self.al.verify_pin(valid_pin)

    def test_verify_pin_allow_empty(self):
        al = AccountLinking(trusted_keys=[],
                            db=self.db,
                            salt="my_salt",
                            email_sender_create_account=EmailFake(),
                            email_sender_pin_recovery=EmailFake(),
                            pin_verify="((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})",
                            pin_empty=False)

        with pytest.raises(ALserviceNotAValidPin):
            al.verify_pin("")
