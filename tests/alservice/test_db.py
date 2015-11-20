import datetime
from unittest.mock import patch

import pytest
from alservice.db import ALDictDatabase, ALdatabase
from alservice.exception import ALserviceDbValidationError

DATABASES = [ALDictDatabase()]
""":type: list[ALdatabase]"""


class TestConsentDB():
    @pytest.fixture(autouse=True)
    def setup(self):
        self.ticket = "ticket_123"

    @pytest.mark.parametrize("database", DATABASES)
    def test_validation(self, database: ALdatabase):
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
    def test_get_uuid(self, database: ALdatabase):
        database.create_account("email_hash", "pin_hash", "my_uuid")
        database.create_link("my_key", "my_idp", "my_email_hash")
        uuid = database.get_uuid("my_key")
        assert uuid == "my_uuid", "Wrong uuid"

    @pytest.mark.parametrize("database", DATABASES)
    def test_save_ticket_state(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_save_token_state(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_get_token_state(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_get_ticket_state(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_create_account(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_create_link(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_verify_account(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_remove_ticket_state(self, database: ALdatabase):
        pass

    @pytest.mark.parametrize("database", DATABASES)
    def test_remove_token_state(self, database: ALdatabase):
        pass
