import logging
import sys
from importlib import import_module

import pkg_resources
from flask.app import Flask
from flask.helpers import url_for
from flask_babel import Babel
from flask_mako import MakoTemplates
from jwkest.jwk import rsa_load, RSAKey
from mako.lookup import TemplateLookup
from sqlalchemy.orm import session

from alservice.al import EmailSmtp, AccountLinking
from alservice.db import ALdatabase
from alservice.service.views import get_browser_lang


def get_locale():
    try:
        return session["language"]
    except:
        return get_browser_lang()


def import_database_class(db_class):
    path, _class = db_class.rsplit('.', 1)
    module = import_module(path)
    database_class = getattr(module, _class)
    return database_class


def init_account_linking(app: Flask):
    trusted_keys = [RSAKey(key=rsa_load(path)) for path in app.config["JWT_PUB_KEY"]]
    salt = app.config["SALT"]

    with open(app.config["MESSAGE_TEMPLATE"]) as f:
        message = f.read()

    message_from = app.config["MESSAGE_FROM"]
    message_subject = app.config["MESSAGE_SUBJECT"]
    smtp_server = app.config["SMTP_SERVER"]
    verify_url = "{}/verify_token".format(url_for('account_linking_service.verify_token'), _external=True)

    email_sender = EmailSmtp(message_subject, message, message_from, smtp_server, verify_url)
    database_class = import_database_class(app.config['DATABASE_CLASS_PATH'])
    if not issubclass(database_class, ALdatabase):
        raise ValueError("%s does not inherit from ALdatabase" % database_class)
    database = database_class(*app.config['DATABASE_CLASS_PARAMETERS'])

    al = AccountLinking(trusted_keys, database, salt, email_sender, pin_verify=app.config["PIN_CHECK"],
                        pin_empty=app.config["PIN_EMPTY"])

    return al


def setup_logging(logging_level: str):
    logger = logging.getLogger("")
    base_formatter = logging.Formatter("[%(asctime)-19.19s] [%(levelname)-5.5s]: %(message)s")
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(base_formatter)
    hdlr.setLevel(logging_level)
    logger.addHandler(hdlr)


def create_app(config: dict = {}):
    app = Flask(__name__, static_folder='static')

    if config:
        app.config.update(config)
    else:
        app.config.from_envvar('ALSERVICE_CONFIG')

    MakoTemplates(app)
    app._mako_lookup = TemplateLookup(directories=[pkg_resources.resource_filename('alservice.service', 'templates')],
                                      input_encoding='utf-8', output_encoding='utf-8',
                                      imports=['from flask_babel import gettext as _'])

    app.al = init_account_linking(app)

    babel = Babel(app)
    babel.localeselector(get_locale)

    from .views import account_linking_views
    app.register_blueprint(account_linking_views)

    setup_logging(app.config.get('LOGGING_LEVEL', 'INFO'))
    return app
