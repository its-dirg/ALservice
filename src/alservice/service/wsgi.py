import logging
import sys

import pkg_resources
from flask.app import Flask
from flask.globals import session
from flask_babel import Babel
from flask_mako import MakoTemplates
from jwkest.jwk import rsa_load, RSAKey
from mako.lookup import TemplateLookup

from alservice.al import AccountLinking
from alservice.db import ALDatasetDatabase
from alservice.mail import EmailSmtp, Email
from alservice.service.views import get_browser_lang


def get_locale():
    try:
        return session["language"]
    except KeyError:
        return get_browser_lang()


def init_account_linking(app: Flask, mail_client: Email = None):
    trusted_keys = [RSAKey(key=rsa_load(path)) for path in app.config["JWT_PUB_KEY"]]
    salt = app.config["SALT"]

    with open(app.config["MESSAGE_TEMPLATE"]) as f:
        message = f.read()

    message_from = app.config["MESSAGE_FROM"]
    message_subject = app.config["MESSAGE_SUBJECT"]
    smtp_server = app.config["SMTP_SERVER"]

    email_sender = mail_client or EmailSmtp(message_subject, message, message_from, smtp_server)
    database = ALDatasetDatabase(app.config.get("DATABASE_URL"))

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


def create_app(config: dict = {}, mail_client=None):
    app = Flask(__name__, static_folder='static')

    if config:
        app.config.update(config)
    else:
        app.config.from_envvar('ALSERVICE_CONFIG')

    MakoTemplates(app)
    app._mako_lookup = TemplateLookup(directories=[pkg_resources.resource_filename('alservice.service', 'templates')],
                                      input_encoding='utf-8', output_encoding='utf-8',
                                      imports=['from flask_babel import gettext as _'])

    app.al = init_account_linking(app, mail_client)

    babel = Babel(app)
    babel.localeselector(get_locale)
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = pkg_resources.resource_filename('alservice.service',
                                                                                  'data/i18n/locales')

    from .views import account_linking_views
    app.register_blueprint(account_linking_views)

    setup_logging(app.config.get('LOGGING_LEVEL', 'INFO'))
    return app
