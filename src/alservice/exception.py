__author__ = 'haho0032'


class ALserviceError(Exception):
    pass


class ALserviceTokenError(ALserviceError):
    pass

class ALserviceAuthenticationError(ALserviceError):
    pass