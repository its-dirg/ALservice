import datetime
from datetime import datetime

import pytest

from alservice.db import AccountLinkingDB, ALDatasetDatabase
from alservice.exception import ALserviceDbValidationError, ALserviceDbNotUniqueTokenError, \
    ALserviceDbValueDoNotExistsError, ALserviceDbKeyDoNotExistsError


@pytest.fixture
def database():
    return ALDatasetDatabase()


class TestDB():
    def test_validation(self, database):
        data = {
            "key1": None,
            "key2": {"foo": "bar"}
        }

        with pytest.raises(ALserviceDbValidationError) as exc:
            database.validation(data)

        assert all(k in str(exc.value) for k in data.keys())

    def test_get_uuid_should_raise_exception_for_unknown_key(self, database):
        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_uuid("unknown")

    def test_get_uuid_should_raise_exception_for_invalid_key(self, database):
        with pytest.raises(ALserviceDbValidationError):
            database.get_uuid("")

    def test_get_uuid(self, database):
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")

        uuid = database.get_uuid("my_key")
        assert uuid == "my_uuid"

    def test_save_ticket_state_and_test_get_ticket_state(self, database):
        database.save_ticket_state("my_ticket", "my_key", "my_idp", "my_redirect")
        ticket_state = database.get_ticket_state("my_ticket")
        assert ticket_state.redirect == "my_redirect"
        assert ticket_state.idp == "my_idp"
        assert ticket_state.key == "my_key"
        assert ticket_state.timestamp < datetime.now()

    def test_save_ticket_state_should_raise_exception_for_duplicate_ticket(self, database):
        ticket = "my_ticket"
        database.save_ticket_state(ticket, "my_key", "my_idp", "my_redirect")

        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.save_ticket_state(ticket, "my_key2", "my_idp2", "my_redirect2")

    def test_save_ticket_state_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.save_ticket_state(None, "", 3, 8)

        assert all(k in str(exc.value) for k in [AccountLinkingDB.TICKET, AccountLinkingDB.KEY, AccountLinkingDB.IDP,
                                                 AccountLinkingDB.REDIRECT])

    def test_get_ticket_state_should_raise_exception_for_invalid_ticket(self, database):
        with pytest.raises(ALserviceDbValidationError):
            database.get_ticket_state("")

    def test_save_token_state_and_get_token_state(self, database):
        database.save_token_state("my_token", "my_email_hash")
        token_state = database.get_token_state("my_token")
        assert token_state.email_hash == "my_email_hash"
        assert token_state.timestamp < datetime.now()

    def test_save_token_state_should_raise_exception_for_duplicate_ticket(self, database):
        token = "my_token"
        database.save_token_state(token, "my_email_hash")
        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.save_token_state(token, "my_email_hash")

    def test_save_token_state_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.save_token_state(3, "")

        assert all(k in str(exc.value) for k in [AccountLinkingDB.TOKEN, AccountLinkingDB.EMAIL_HASH])

    def test_get_token_state_should_raise_exception_for_invalid_token(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.get_token_state("")

    def test_create_account_verify_account(self, database):
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        database.verify_account("my_email_hash", "my_pin_hash")

    def test_verify_account_should_raise_exception_for_wrong_pin_hash(self, database):
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        with pytest.raises(ALserviceDbValueDoNotExistsError):
            database.verify_account("my_email_hash", "other_pin_hash")

    def test_verify_account_should_raise_exception_for_wrong_email_hash(self, database):
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.verify_account("other_email_hash", "my_pin_hash")

    def test_verify_account_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.verify_account(1, "")

        assert all(k in str(exc.value) for k in [AccountLinkingDB.EMAIL_HASH, AccountLinkingDB.PIN_HASH])

    def test_create_account_should_raise_exception_for_duplicate_email_hash(self, database):
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")

        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.create_account("my_email_hash", "my_pin_hash", "my_uuid")

    def test_create_account_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.create_account(None, "", 2)
        assert all(k in str(exc.value) for k in
                   [AccountLinkingDB.EMAIL_HASH, AccountLinkingDB.PIN_HASH, AccountLinkingDB.UUID])

    def test_create_link(self, database):
        uuid = "my_uuid"
        key = "my_key"
        database.create_account("email_hash", "pin_hash", uuid)
        database.create_link(key, "my_idp", "email_hash")
        assert database.get_uuid(key) == uuid

    def test_create_link_should_raise_exception_for_duplicate_key(self, database):
        key = "my_key"
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link(key, "my_idp", "my_email_hash")

        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.create_link(key, "my_idp", "other_email_hash")

    def test_create_link_should_raise_exception_for_invalid_data(self, database):
        database.create_account("email_hash", "pin_hash", "my_uuid")
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.create_link(None, "", 1)

        assert all(
            k in str(exc.value) for k in [AccountLinkingDB.KEY, AccountLinkingDB.IDP, AccountLinkingDB.EMAIL_HASH])

    def test_remove_link(self, database):
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")

        database.remove_link("email_hash", "my_idp")

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_uuid("my_key")

    def test_remove_link(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.remove_link("", 1)
        assert all(k in str(exc.value) for k in [AccountLinkingDB.IDP, AccountLinkingDB.EMAIL_HASH])

    def test_remove_ticket_state(self, database):
        ticket = "my_ticket"

        database.save_ticket_state(ticket, "my_key", "my_idp", "my_redirect")
        assert database.get_ticket_state(ticket)

        database.remove_ticket_state(ticket)

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_ticket_state(ticket)

    def test_remove_ticket_state(self, database):
        with pytest.raises(ALserviceDbValidationError):
            database.remove_ticket_state("")

    def test_remove_token_state(self, database):
        token = "my_token"

        database.save_token_state(token, "my_email_hash")
        assert database.get_token_state("my_token")

        database.remove_token_state(token)

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_token_state(token)

    def test_remove_token_state_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError):
            database.remove_token_state("")

    def test_remove_account(self, database):
        email_hash = "email_hash"
        database.create_account(email_hash, "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")
        assert database.get_uuid("my_key")

        database.remove_account(email_hash)

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_uuid("my_key")

    def test_remove_account_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError):
            database.remove_account("")

    def test_change_pin(self, database):
        old_pin = "old_pin"
        new_pin = "new_pin"
        database.create_account("email_hash", old_pin, "my_uuid")
        database.verify_account("email_hash", old_pin)
        database.change_pin("email_hash", old_pin, new_pin)
        database.verify_account("email_hash", new_pin)

    def test_change_pin_should_raise_exception_for_invalid_data(self, database):
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.change_pin(None, "", 1)
        assert all(k in str(exc.value) for k in
                   [AccountLinkingDB.EMAIL_HASH, AccountLinkingDB.OLD_PIN_HASH, AccountLinkingDB.NEW_PIN_HASH])

    def test_create_multiple_account_links(self, database):
        email = "email_hash"
        database.create_link("my_key", "my_idp", email)
        database.create_link("my_key2", "my_idp2", email)
        account_list = database._get_account_link_data(email)
        assert len(account_list) == 2
