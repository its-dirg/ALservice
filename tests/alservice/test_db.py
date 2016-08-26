import datetime
from datetime import datetime
from unittest.mock import patch

import pytest
from alservice.db import ALDictDatabase, AccountLinkingDB, ALSQLiteDatabase
from alservice.exception import ALserviceDbValidationError, ALserviceDbNotUniqueTokenError, \
    ALserviceDbValueDoNotExistsError, ALserviceDbKeyDoNotExistsError

DATABASES = [ALDictDatabase(), ALSQLiteDatabase()]
""":type: list[ALdatabase]"""


class TestDB():
    @pytest.fixture(autouse=True)
    def setup(self):
        for db in DATABASES:
            db.db_clear()

    @pytest.mark.parametrize("database", DATABASES)
    def test_validation(self, database: AccountLinkingDB):
        _dict = {
            "key1": None,
            "key2": ALDictDatabase()
        }
        try:
            database.validation(_dict)
        except ALserviceDbValidationError as error:
            assert ("key1" in error.message and "key2" in error.message),\
                "All keys must be in the message"
        except Exception:
            assert False, "Wrong exception"
        _dict = {
            "key1": None,
            "key2": ALDictDatabase()
        }
        try:
            database.validation(_dict)
        except ALserviceDbValidationError as error:
            assert "key1" in error.message and "key2" in error.message, \
                "All keys must be in the message"
        except Exception:
            assert False, "Wrong exception"

    @pytest.mark.parametrize("database", DATABASES)
    def test_get_uuid(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"
        _error = None
        try:
            uuid = database.get_uuid("my_key")
        except ALserviceDbKeyDoNotExistsError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbKeyDoNotExistsError!"
        database.create_account("email_hash", "pin_hash", "my_uuid")
        try:
            uuid = database.get_uuid("my_key")
        except ALserviceDbKeyDoNotExistsError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbKeyDoNotExistsError!"
        database.create_link("my_key", "my_idp", "email_hash")
        uuid = database.get_uuid("my_key")
        assert uuid == "my_uuid", "Wrong uuid"
        _error = None
        try:
            ticket_state = database.get_uuid("")
        except ALserviceDbValidationError as error:
            _error = error
            assert AccountLinkingDB.KEY in error.message, "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_save_ticket_state_and_test_get_ticket_state(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"

        database.save_ticket_state("my_ticket", "my_key", "my_idp", "my_redirect")
        ticket_state = database.get_ticket_state("my_ticket")
        assert ticket_state.redirect == "my_redirect"
        assert ticket_state.idp == "my_idp"
        assert ticket_state.key == "my_key"
        assert ticket_state.timestamp < datetime.now()
        _error = None
        try:
            database.save_ticket_state("my_ticket", "my_key", "my_idp", "my_redirect")
        except ALserviceDbNotUniqueTokenError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbNotUniqueTokenError!"
        _error = None
        try:
            database.save_ticket_state(None, "", 3, 8)
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.TICKET in error.message and
                    AccountLinkingDB.KEY in error.message and
                    AccountLinkingDB.IDP in error.message and
                    AccountLinkingDB.REDIRECT in error.message),\
                "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"
        _error = None
        try:
            ticket_state = database.get_ticket_state("")
        except ALserviceDbValidationError as error:
            _error = error
            assert "ticket" in error.message, "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_save_token_state_and_get_token_state(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"

        database.save_token_state("my_token", "my_email_hash")
        token_state = database.get_token_state("my_token")
        assert token_state.email_hash == "my_email_hash"
        assert token_state.timestamp < datetime.now()
        _error = None
        try:
            database.save_token_state("my_token", "my_email_hash")
        except ALserviceDbNotUniqueTokenError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbNotUniqueTokenError!"
        _error = None
        try:
            database.save_token_state(3, "")
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.TOKEN in error.message and
                    AccountLinkingDB.EMAIL_HASH in error.message),\
                "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"
        _error = None
        try:
            database.get_token_state("")
        except ALserviceDbValidationError as error:
            _error = error
            assert "token" in error.message, "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_create_account_verify_account(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"

        database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        database.verify_account("my_email_hash", "my_pin_hash")
        _error = None
        try:
            database.verify_account("my_email_hash", "my_pin_hash_1")
        except ALserviceDbValueDoNotExistsError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbValueDoNotExistsError!"
        _error = None
        try:
            database.verify_account("my_email_hash_1", "my_pin_hash")
        except ALserviceDbKeyDoNotExistsError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbValueDoNotExistsError!"
        _error = None
        try:
            database.create_account("my_email_hash", "my_pin_hash", "my_uuid")
        except ALserviceDbNotUniqueTokenError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbNotUniqueTokenError!"
        _error = None
        try:
            database.create_account(None, "", 2)
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.EMAIL_HASH in error.message and
                    AccountLinkingDB.PIN_HASH in error.message and
                    AccountLinkingDB.UUID in error.message),\
                "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"
        _error = None
        try:
            database.verify_account(1, "")
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.EMAIL_HASH in error.message and
                    AccountLinkingDB.PIN_HASH in error.message),\
                "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_create_link(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")
        uuid = database.get_uuid("my_key")
        assert uuid == "my_uuid", "Wrong uuid"
        _error = None
        try:
            database.create_link("my_key", "my_idp", "email_hash_1")
        except ALserviceDbNotUniqueTokenError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbNotUniqueTokenError!"
        _error = None
        try:
            database.create_link(None, "", 1)
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.KEY in error.message and
                    AccountLinkingDB.IDP in error.message and
                    AccountLinkingDB.EMAIL_HASH in error.message),\
                "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_remove_link(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")
        uuid = database.get_uuid("my_key")
        assert uuid == "my_uuid", "Wrong uuid"
        database.remove_link("email_hash_1", "my_idp")
        database.remove_link("email_hash_1", "my_idp_1")
        database.remove_link("email_hash", "my_idp_1")
        database.remove_link("email_hash", "my_idp")
        _error = None
        try:
            uuid = database.get_uuid("my_key")
        except ALserviceDbKeyDoNotExistsError as error:
            _error = error
        assert _error is not None, "Must be an ALserviceDbKeyDoNotExistsError!"
        try:
            database.remove_link("", 1)
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.IDP in error.message and
                    AccountLinkingDB.EMAIL_HASH in error.message),\
                "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_remove_ticket_state(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"

        database.save_ticket_state("my_ticket", "my_key", "my_idp", "my_redirect")
        ticket_state = database.get_ticket_state("my_ticket")
        assert ticket_state is not None
        ticket_state = database.remove_ticket_state("my_ticket_1")
        ticket_state = database.remove_ticket_state("my_ticket")
        assert database.db_empty(), "Database must be empty to run test!"
        _error = None
        try:
            ticket_state = database.remove_ticket_state("")
        except ALserviceDbValidationError as error:
            _error = error
            assert AccountLinkingDB.TICKET in error.message, "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_remove_token_state(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"

        database.save_token_state("my_token", "my_email_hash")
        token_state = database.get_token_state("my_token")
        assert token_state is not None
        ticket_state = database.remove_token_state("my_token_1")
        ticket_state = database.remove_token_state("my_token")
        assert database.db_empty(), "Database must be empty to run test!"
        _error = None
        try:
            ticket_state = database.remove_token_state("")
        except ALserviceDbValidationError as error:
            _error = error
            assert AccountLinkingDB.TOKEN in error.message, "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_remove_account(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "email_hash")
        uuid = database.get_uuid("my_key")
        assert uuid is not None
        database.remove_account("email_hash_!")
        database.remove_account("email_hash")
        assert database.db_empty(), "Database must be empty to run test!"
        _error = None
        try:
            database.remove_account("")
        except ALserviceDbValidationError as error:
            _error = error
            assert AccountLinkingDB.EMAIL_HASH in error.message, "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_change_pin(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.verify_account("email_hash", "pin_hash")
        database.change_pin("email_hash", "pin_hash", "pin_hash_1")
        database.verify_account("email_hash", "pin_hash_1")
        _error = None
        try:
            database.change_pin(None, "", 1)
        except ALserviceDbValidationError as error:
            _error = error
            assert (AccountLinkingDB.EMAIL_HASH in error.message and
                    AccountLinkingDB.OLD_PIN_HASH in error.message and
                    AccountLinkingDB.NEW_PIN_HASH in error.message), "All keys must be in the message"
        assert _error is not None, "Must be an ALserviceDbValidationError!"

    @pytest.mark.parametrize("database", DATABASES)
    def test_create_multiple_account_links(self, database: AccountLinkingDB):
        assert database.db_empty(), "Database must be empty to run test!"
        email = "email_hash"
        database.create_link("my_key", "my_idp", email)
        database.create_link("my_key2", "my_idp2", email)
        account_list = database._get_account_link_data(email)
        assert len(account_list) == 2


