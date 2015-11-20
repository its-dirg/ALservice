__author__ = 'haho0032'


class ALserviceError(Exception):

    def __init__(self, message, *args, **kwargs):
        super(ALserviceError).__init__(*args, **kwargs)
        self.message = message


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
