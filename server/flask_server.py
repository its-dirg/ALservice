from importlib import import_module
import logging
from logging.handlers import RotatingFileHandler
from flask.ext.babel import Babel
from flask.ext.mako import MakoTemplates, render_template
from flask.helpers import send_from_directory
from jwkest.jwk import rsa_load, RSAKey
from mako.lookup import TemplateLookup
from flask import Flask
from flask import abort
from flask import request
from flask import session
from flask import redirect
from alservice.al import AccountLinking, JWTHandler, Email, EmailSmtp
from alservice.db import ALDictDatabase, ALdatabase
from alservice.exception import ALserviceAuthenticationError, ALserviceTokenError, \
    ALserviceNoSuchKey, ALserviceNotAValidPin
from urllib.parse import parse_qs

app = Flask(__name__, static_folder='static')
babel = Babel(app)


@babel.localeselector
def get_locale():
    try:
        return session["language"]
    except:
        return get_browser_lang()


@app.route("/static/<path:path>")
def get_static(path):
    return send_from_directory('', path)


def get_browser_lang():
    return request.accept_languages.best_match(['sv', 'en'])


def change_language():
    if "language" not in session:
        session["language"] = get_browser_lang()
    if ("lang" in request.form):
        session["language"] = request.form["lang"]
        return True
    return False


@app.route("/get_id")
def get_id():
    parsed_qs = parse_qs(request.query_string.decode())
    jwt = None
    try:
        jwt = parsed_qs["jwt"][0]
    except KeyError:
        abort(401)
    jso = JWTHandler.unpack_jwt(jwt, keys)
    key = JWTHandler.key(jso)
    try:
        uuid = al.get_uuid(key)
    except ALserviceNoSuchKey:
        # TODO Need the idp and redirect. Using protected function
        ticket = al.create_ticket(key, jso["idp"], jso["redirect_endpoint"])
        return ticket, 400
    return uuid, 200


@app.route("/approve/<ticket>", methods=['POST', 'GET'])
def approve(ticket):
    if not change_language():
        session["ticket"] = ticket
        if request.method == 'POST':
            email = request.form["email"]
            pin = request.form["pin"]
            try:
                redirect_url = al.get_redirect_url(ticket)
                al.link_key(email, pin, ticket)
                return redirect(redirect_url)
            except ALserviceAuthenticationError:
                return render_template('login.mako',
                                       name="mako",
                                       form_action='/approve/%s' % ticket,
                                       ticket=ticket,
                                       login_failed_message=True,
                                       language=session["language"])

    return render_template('login.mako',
                           name="mako",
                           form_action='/approve/%s' % ticket,
                           ticket=ticket,
                           login_failed_message=False,
                           language=session["language"])


@app.route("/create_account", methods=["POST"])
def create_account():
    change_language()
    return render_template('create_account.mako',
                           name="mako",
                           form_action='/create_account',
                           language=session["language"])


@app.route("/send_token", methods=["POST", "GET"])
def send_token():
    if not change_language():
        email = None
        ticket = None
        try:
            try:
                email = request.form["email"]
                session["email"] = email
            except KeyError:
                email = session["email"]
            ticket = session["ticket"]
        except KeyError:
            abort(401)
        al.create_account_step1(email, ticket)
    return render_template("token_was_sent.mako",
                           name="mako",
                           form_action='/send_token',
                           email=session["email"],
                           token_error=False,
                           language=session["language"])

@app.route("/verify_token", methods=["POST"])
def verify_token():
    if not change_language():
        # parsed_qs = parse_qs(request.query_string.decode())
        # if "token" in parsed_qs:
        #     session["token"] = parsed_qs["token"][0]
        if "token" in request.form:
            session["token"] = request.form["token"]
        try:
            token = session["token"]
            al.create_account_step2(token)
        except ALserviceTokenError:
            return render_template("token_was_sent.mako",
                                   name="mako",
                                   form_action='/verify_token',
                                   email=session["email"],
                                   token_error=True,
                                   language=session["language"])
        except KeyError:
            abort(500)

    return render_template("save_account.mako",
                           name="mako",
                           form_action='/verify_token',
                           pin_error=False,
                           language=session["language"])


def import_database_class():
    db_module = app.config['DATABASE_CLASS_PATH']
    path, _class = db_module.rsplit('.', 1)
    module = import_module(path)
    database_class = getattr(module, _class)
    return database_class


@app.route("/save_account", methods=["POST"])
def verify_pin():
    pin = request.form["pin"]
    token = session["token"]
    redirect_url = al.get_redirect_url(token)
    try:
        al.create_account_step3(token, pin)
    except ALserviceNotAValidPin:
        return render_template("save_account.mako",
                               name="mako",
                               form_action='/verify_token',
                               pin_error=True,
                               language=session["language"])
    return redirect(redirect_url)


class MustInheritFromALdatabase(Exception):
    pass

if __name__ == "__main__":
    import ssl
    app.config.from_pyfile("settings.cfg")
    LOGGER = logging.getLogger("alservice")
    hdlr = logging.FileHandler(app.config["LOG_FILE"])
    base_formatter = logging.Formatter("[%(asctime)-19.19s] [%(levelname)-5.5s]: %(message)s")
    hdlr.setLevel(app.config["LOG_LEVEL"])
    hdlr.setFormatter(base_formatter)
    LOGGER.addHandler(hdlr)
    LOGGER.setLevel(logging.DEBUG)
    mako = MakoTemplates()
    mako.init_app(app)
    app._mako_lookup = TemplateLookup(directories=["templates"],
                                      input_encoding='utf-8', output_encoding='utf-8',
                                      imports=["from flask.ext.babel import gettext as _"])
    context = None
    if app.config['SSL']:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_cert_chain(app.config["SERVER_CERT"], app.config["SERVER_KEY"])
    global keys
    global al
    keys = []
    for key in app.config["JWT_PUB_KEY"]:
        _bkey = rsa_load(key)
        pub_key = RSAKey().load_key(_bkey)
        keys.append(pub_key)
    salt = app.config["SALT"]

    message = open(app.config["MESSAGE_TEMPLATE"], "r").read()
    message_from = app.config["MESSAGE_FROM"]
    message_subject = app.config["MESSAGE_SUBJECT"]
    smtp_server = app.config["SMTP_SERVER"]
    verify_url = "%s://%s:%s/verify_token" % ("https" if context else "http",
                                              app.config['HOST'],
                                              app.config['PORT'])

    email_sender = EmailSmtp(message_subject, message, message_from, smtp_server, verify_url)
    database_class = import_database_class()
    if not issubclass(database_class, ALdatabase):
        raise MustInheritFromALdatabase("%s does not inherit from ALdatabase" % database_class)
    database = database_class(*app.config['DATABASE_CLASS_PARAMETERS'])

    al = AccountLinking(database, salt, email_sender, pin_verify=app.config["PIN_CHECK"],
                        pin_empty=app.config["PIN_EMPTY"])
    
    app.secret_key = app.config['SECRET_SESSION_KEY']
    app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
            ssl_context=context)
