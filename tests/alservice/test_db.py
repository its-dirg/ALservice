import datetime
from datetime import datetime

import pytest

from alservice.db import ALDictDatabase, AccountLinkingDB, ALSQLiteDatabase
from alservice.exception import ALserviceDbValidationError, ALserviceDbNotUniqueTokenError, \
    ALserviceDbValueDoNotExistsError, ALserviceDbKeyDoNotExistsError

DATABASES = [ALDictDatabase, ALSQLiteDatabase]


class TestDB():
    @pytest.mark.parametrize("db_class", DATABASES)
    def test_validation(self, db_class):
        database = db_class()
        data = {
            "key1": None,
            "key2": ALDictDatabase()
        }

        with pytest.raises(ALserviceDbValidationError) as exc:
            database.validation(data)

        assert all(k in str(exc.value) for k in data.keys())

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_get_uuid_should_raise_exception_for_unknown_key(self, db_class):
        database = db_class()

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_uuid("unknown")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_get_uuid_should_raise_exception_for_invalid_key(self, db_class):
        database = db_class()

        with pytest.raises(ALserviceDbValidationError):
            database.get_uuid("")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_get_uuid(self, db_class):
        database = db_class()
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")

        uuid = database.get_uuid("my_key")
        assert uuid == "my_uuid"

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_save_ticket_state_and_test_get_ticket_state(self, db_class):
        database = db_class()
        database.save_ticket_state("my_ticket", "my_key", "my_idp", "my_redirect")
        ticket_state = database.get_ticket_state("my_ticket")
        assert ticket_state.redirect == "my_redirect"
        assert ticket_state.idp == "my_idp"
        assert ticket_state.key == "my_key"
        assert ticket_state.timestamp < datetime.now()

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_save_ticket_state_should_raise_exception_for_duplicate_ticket(self, db_class):
        database = db_class()
        ticket = "my_ticket"
        database.save_ticket_state(ticket, "my_key", "my_idp", "my_redirect")

        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.save_ticket_state(ticket, "my_key2", "my_idp2", "my_redirect2")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_save_ticket_state_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()

        with pytest.raises(ALserviceDbValidationError) as exc:
            database.save_ticket_state(None, "", 3, 8)

        assert all(k in str(exc.value) for k in [AccountLinkingDB.TICKET, AccountLinkingDB.KEY, AccountLinkingDB.IDP,
                                                 AccountLinkingDB.REDIRECT])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_get_ticket_state_should_raise_exception_for_invalid_ticket(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError):
            database.get_ticket_state("")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_save_token_state_and_get_token_state(self, db_class):
        database = db_class()

        database.save_token_state("my_token", "my_email_hash")
        token_state = database.get_token_state("my_token")
        assert token_state.email_hash == "my_email_hash"
        assert token_state.timestamp < datetime.now()

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_save_token_state_should_raise_exception_for_duplicate_ticket(self, db_class):
        token = "my_token"
        database = db_class()
        database.save_token_state(token, "my_email_hash")
        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.save_token_state(token, "my_email_hash")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_save_token_state_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.save_token_state(3, "")

        assert all(k in str(exc.value) for k in [AccountLinkingDB.TOKEN, AccountLinkingDB.EMAIL_HASH])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_get_token_state_should_raise_exception_for_invalid_token(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.get_token_state("")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_account_verify_account(self, db_class):
        database = db_class()
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        database.verify_account("my_email_hash", "my_pin_hash")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_verify_account_should_raise_exception_for_wrong_pin_hash(self, db_class):
        database = db_class()
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        with pytest.raises(ALserviceDbValueDoNotExistsError):
            database.verify_account("my_email_hash", "other_pin_hash")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_verify_account_should_raise_exception_for_wrong_email_hash(self, db_class):
        database = db_class()
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.verify_account("other_email_hash", "my_pin_hash")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_verify_account_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.verify_account(1, "")

        assert all(k in str(exc.value) for k in [AccountLinkingDB.EMAIL_HASH, AccountLinkingDB.PIN_HASH])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_account_should_raise_exception_for_duplicate_email_hash(self, db_class):
        database = db_class()
        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")

        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.create_account("my_email_hash", "my_pin_hash", "my_uuid")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_account_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()

        with pytest.raises(ALserviceDbValidationError) as exc:
            database.create_account(None, "", 2)
        assert all(k in str(exc.value) for k in
                   [AccountLinkingDB.EMAIL_HASH, AccountLinkingDB.PIN_HASH, AccountLinkingDB.UUID])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_link(self, db_class):
        uuid = "my_uuid"
        key = "my_key"
        database = db_class()
        database.create_account("email_hash", "pin_hash", uuid)
        database.create_link(key, "my_idp", "email_hash")
        assert database.get_uuid(key) == uuid

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_link_should_raise_exception_for_duplicate_key(self, db_class):
        key = "my_key"
        database = db_class()
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link(key, "my_idp", "my_email_hash")

        with pytest.raises(ALserviceDbNotUniqueTokenError):
            database.create_link(key, "my_idp", "other_email_hash")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_link_should_raise_exception_for_invalid_data(self, db_class):
        key = "my_key"
        database = db_class()
        database.create_account("email_hash", "pin_hash", "my_uuid")
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.create_link(None, "", 1)

        assert all(
            k in str(exc.value) for k in [AccountLinkingDB.KEY, AccountLinkingDB.IDP, AccountLinkingDB.EMAIL_HASH])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_link(self, db_class):
        database = db_class()
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")

        database.remove_link("email_hash", "my_idp")

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_uuid("my_key")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_link(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.remove_link("", 1)
        assert all(k in str(exc.value) for k in [AccountLinkingDB.IDP, AccountLinkingDB.EMAIL_HASH])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_ticket_state(self, db_class):
        ticket = "my_ticket"
        database = db_class()

        database.save_ticket_state(ticket, "my_key", "my_idp", "my_redirect")
        assert database.get_ticket_state(ticket)

        database.remove_ticket_state(ticket)

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_ticket_state(ticket)

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_ticket_state(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError):
            database.remove_ticket_state("")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_token_state(self, db_class):
        token = "my_token"
        database = db_class()

        database.save_token_state(token, "my_email_hash")
        assert database.get_token_state("my_token")

        database.remove_token_state(token)

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_token_state(token)

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_token_state_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()

        with pytest.raises(ALserviceDbValidationError):
            database.remove_token_state("")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_account(self, db_class):
        email_hash = "email_hash"
        database = db_class()
        database.create_account(email_hash, "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")
        assert database.get_uuid("my_key")

        database.remove_account(email_hash)

        with pytest.raises(ALserviceDbKeyDoNotExistsError):
            database.get_uuid("my_key")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_remove_account_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError):
            database.remove_account("")

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_change_pin(self, db_class):
        old_pin = "old_pin"
        new_pin = "new_pin"
        database = db_class()
        database.create_account("email_hash", old_pin, "my_uuid")
        database.verify_account("email_hash", old_pin)
        database.change_pin("email_hash", old_pin, new_pin)
        database.verify_account("email_hash", new_pin)

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_change_pin_should_raise_exception_for_invalid_data(self, db_class):
        database = db_class()
        with pytest.raises(ALserviceDbValidationError) as exc:
            database.change_pin(None, "", 1)
        assert all(k in str(exc.value) for k in
                   [AccountLinkingDB.EMAIL_HASH, AccountLinkingDB.OLD_PIN_HASH, AccountLinkingDB.NEW_PIN_HASH])

    @pytest.mark.parametrize("db_class", DATABASES)
    def test_create_multiple_account_links(self, db_class):
        database = db_class()
        email = "email_hash"
        database.create_link("my_key", "my_idp", email)
        database.create_link("my_key2", "my_idp2", email)
        account_list = database._get_account_link_data(email)
        assert len(account_list) == 2
