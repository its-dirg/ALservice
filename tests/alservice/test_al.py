import pytest

from alservice.al import AccountLinking, Email, IdRequest
from alservice.db import ALDatasetDatabase
from alservice.exception import ALserviceTicketError, \
    ALserviceTokenError, ALserviceAccountExists, ALserviceAuthenticationError, ALserviceNoSuchKey


class EmailFake(Email):
    def __init__(self):
        self.token = None
        self.email_to = None

    def send_mail(self, token: str, email_to: str):
        self.token = token
        self.email_to = email_to


class TestAL(object):
    def create_account(self, pin, email="my_email", id=None, idp=None):
        if id or idp:
            request = IdRequest({"id": id or self.test_id, "idp": idp or self.test_idp,
                                 "redirect_endpoint": "https://client.example.com/redirect"})
        else:
            request = self.account_linking_request
        ticket = self.al.create_ticket(request)
        self.al.create_account_step1(email, ticket)
        assert self.al.email_sender_create_account.email_to == email
        assert self.al.email_sender_create_account.token is not None
        token = self.al.email_sender_create_account.token

        verified_token = self.al.create_account_step2(token)
        assert verified_token == token
        self.al.create_account_step3(token, pin)

    @pytest.fixture(autouse=True)
    def setup(self):
        self.test_idp = "my_idp"
        self.test_id = "my_id"
        self.account_linking_request = IdRequest({"id": self.test_id, "idp": self.test_idp,
                                                  "redirect_endpoint": "https://client.example.com/redirect"})
        self.db = ALDatasetDatabase()
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
        ticket = self.al.create_ticket(self.account_linking_request)
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step2("unknown_token.{}".format(ticket))

    def test_create_account_step3_should_raise_token_exception_for_unknown_token(self):
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step3("incorrect_token", "")

    def test_create_account_step3_should_raise_token_exception_for_unknown_token_and_unknown_ticket(self):
        with pytest.raises(ALserviceTokenError):
            self.al.create_account_step3("incorrect_token.incorrect_ticket", "")

    def test_create_account_step3_should_raise_ticket_exception_for_unknown_token_and_known_ticket(self):
        ticket = self.al.create_ticket(self.account_linking_request)
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        verified_token = self.al.create_account_step2(token)
        broken_token = "{}.unknown_ticket".format(verified_token.split(".")[0], "incorrect_ticket")
        with pytest.raises(ALserviceTicketError):
            self.al.create_account_step3(broken_token, "")

    @pytest.mark.parametrize("pin", ["", "#NotSoEasy1", "ALiteBitHarder#2!435345#fdgdfg"])
    def test_create_account_flow(self, pin):
        self.create_account(pin)

        uuid_1 = self.al.get_uuid(self.account_linking_request.key)
        uuid_2 = self.al.get_uuid(self.account_linking_request.key)
        assert uuid_1 == uuid_2

    def test_create_account_step3_should_raise_exception_if_account_already_exists(self):
        pin = ""
        email = "test@example.com"
        self.create_account(pin, email)

        ticket = self.al.create_ticket(self.account_linking_request)
        self.al.create_account_step1(email, ticket)
        token = self.al.email_sender_create_account.token
        token = self.al.create_account_step2(token)

        with pytest.raises(ALserviceAccountExists):
            self.al.create_account_step3(token, pin)

    def test_link_key_should_raise_exception_if_wrong_pin_is_used(self):
        pin = ""
        self.create_account(pin)

        ticket = self.al.create_ticket(
            IdRequest({"id": "my_id", "idp": self.test_idp, "redirect_endpoint": "my_redirect"}))
        with pytest.raises(ALserviceAuthenticationError):
            self.al.link_key("my_email", "wrong_pin", ticket)

    def test_link_key_should_raise_exception_if_wrong_email_is_used(self):
        pin = ""
        self.create_account(pin)

        ticket = self.al.create_ticket(self.account_linking_request)
        with pytest.raises(ALserviceAuthenticationError):
            self.al.link_key("_wrong_my_email", pin, ticket)

    @pytest.mark.parametrize("pin", ["", "#NotSoEasy1", "ALiteBitHarder#2!435345#fdgdfg"])
    def test_change_account_linking(self, pin):
        email = "test@example.com"
        self.create_account(pin, email)

        new_request = IdRequest({"id": "new_id", "idp": self.account_linking_request["idp"],
                                 "redirect_endpoint": self.account_linking_request["redirect_endpoint"]})
        ticket = self.al.create_ticket(new_request)
        self.al.create_account_step1("my_email", ticket)
        token = self.al.email_sender_create_account.token
        self.al.create_account_step2(token)

        self.al.link_key(email, pin, ticket)
        uuid_1 = self.al.get_uuid(new_request.key)
        uuid_2 = self.al.get_uuid(new_request.key)
        assert uuid_1 == uuid_2

        # the old key has been removed
        with pytest.raises(ALserviceNoSuchKey):
            self.al.get_uuid(self.test_id)

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
            self.al.change_pin_step2(token, pin + "_wrong", pin + "_new")

    def test_change_pin_step2_should_raise_exception_for_unknown_token(self):
        pin = "asdkhAas3#"
        email = "test@example.com"
        self.create_account(pin, email)
        self.al.change_pin_step1(email, pin)

        with pytest.raises(ALserviceAuthenticationError):
            self.al.change_pin_step2("unknown", pin, pin + "_new")

    def test_change_pin(self):
        pin = "#A4534j5khtfdgkjhgkjdfsh#"
        self.create_account(pin)

        self.al.change_pin_step1("my_email", pin)
        token = self.al.email_sender_pin_recovery.token
        new_pin = "my_new_piAAn123123#!"
        self.al.change_pin_step2(token, pin, new_pin)
        ticket = self.al.create_ticket(self.account_linking_request)
        self.al.link_key("my_email", new_pin, ticket)
        uuid_1 = self.al.get_uuid(self.account_linking_request.key)
        uuid_2 = self.al.get_uuid(self.account_linking_request.key)
        assert uuid_1 == uuid_2

    @pytest.mark.parametrize("invalid_pin", [
        None,
        "NotOK",
    ])
    def test_verify_pin_for_invalid_pin(self, invalid_pin):
        assert self.al._verify_pin(invalid_pin) is False

    @pytest.mark.parametrize("valid_pin", [
        "aP1n##",
        ""
    ])
    def test_verify_pin(self, valid_pin):
        # should not raise an exception
        self.al._verify_pin(valid_pin)

    def test_verify_pin_allow_empty(self):
        al = AccountLinking(trusted_keys=[],
                            db=self.db,
                            salt="my_salt",
                            email_sender_create_account=EmailFake(),
                            email_sender_pin_recovery=EmailFake(),
                            pin_verify="((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})",
                            pin_empty=False)

        assert al._verify_pin("") is False
