"""
All exceptions for the account linking service.
"""


class ALserviceError(Exception):

    def __init__(self, message=None, *args, **kwargs):
        super(ALserviceError).__init__(*args, **kwargs)
        self.message = message


class ALserviceNotAValidPin(ALserviceError):
    pass


class ALserviceNoSuchKey(ALserviceError):
    pass


class ALserviceAccountExists(ALserviceError):
    pass


class ALserviceTicketError(ALserviceError):
    pass


class ALserviceTokenError(ALserviceError):
    pass


class ALserviceAuthenticationError(ALserviceError):
    pass


class ALserviceDbError(ALserviceError):
    pass


class ALserviceDbKeyDoNotExistsError(ALserviceDbError):
    pass


class ALserviceDbValueDoNotExistsError(ALserviceDbError):
    pass


class ALserviceDbUnknownError(ALserviceDbError):
    pass


class ALserviceDbNotUniqueTokenError(ALserviceDbError):
    pass


class ALserviceDbValidationError(ALserviceDbError):
    pass
