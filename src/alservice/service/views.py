from urllib.parse import parse_qs

from flask.blueprints import Blueprint
from flask.globals import request, current_app, session
from flask.helpers import send_from_directory
from flask_mako import render_template
from werkzeug.exceptions import abort
from werkzeug.utils import redirect

from alservice.al import JWTHandler
from alservice.exception import ALserviceNoSuchKey, ALserviceAuthenticationError, ALserviceTokenError, \
    ALserviceTicketError, ALserviceNotAValidPin

account_linking_views = Blueprint('account_linking_service', __name__, url_prefix='')


@account_linking_views.route("/static/<path:path>")
def get_static(path):
    return send_from_directory('', path)


@account_linking_views.route("/get_id")
def get_id():
    parsed_qs = parse_qs(request.query_string.decode())
    jwt = None
    try:
        jwt = parsed_qs["jwt"][0]
    except KeyError:
        abort(400)
    jso = JWTHandler.unpack_jwt(jwt, current_app.al.trusted_keys) # TODO don't dig out trusted_keys like this
    key = JWTHandler.key(jso)
    try:
        uuid = current_app.al.get_uuid(key)
    except ALserviceNoSuchKey:
        ticket = current_app.al.create_ticket(key, jso["idp"], jso["redirect_endpoint"])
        return ticket, 404
    return uuid, 200


@account_linking_views.route("/approve/<ticket>", methods=['POST', 'GET'])
def approve(ticket):
    if not change_language():
        session["ticket"] = ticket
        if request.method == 'POST':
            email = request.form["email"]
            pin = request.form["pin"]
            try:
                redirect_url = current_app.al.get_redirect_url(ticket)
                current_app.al.link_key(email, pin, ticket)
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


@account_linking_views.route("/create_account", methods=["POST"])
def create_account():
    change_language()
    return render_template('create_account.mako',
                           name="mako",
                           form_action='/create_account',
                           language=session["language"])


@account_linking_views.route("/send_token", methods=["POST", "GET"])
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
            abort(400)
        current_app.al.create_account_step1(email, ticket)
    return render_template("token_was_sent.mako",
                           name="mako",
                           form_action='/send_token',
                           email=session["email"],
                           token_error=False,
                           language=session["language"])


@account_linking_views.route("/verify_token", methods=["POST"])
def verify_token():
    if not change_language():
        if "token" in request.form:
            session["token"] = request.form["token"]
        try:
            token = session["token"]
            current_app.al.create_account_step2(token)
        except (ALserviceTokenError, ALserviceTicketError):
            return render_template("token_was_sent.mako",
                                   name="mako",
                                   form_action='/verify_token',
                                   email=session["email"],
                                   token_error=True,
                                   language=session["language"])
        except KeyError:
            abort(400)

    return render_template("save_account.mako",
                           name="mako",
                           form_action='/verify_token',
                           pin_error=False,
                           language=session["language"])


@account_linking_views.route("/save_account", methods=["POST"])
def verify_pin():
    pin = request.form["pin"]
    token = session["token"]
    redirect_url = current_app.al.get_redirect_url(token)
    try:
        current_app.al.create_account_step3(token, pin)
    except ALserviceNotAValidPin:
        return render_template("save_account.mako",
                               name="mako",
                               form_action='/verify_token',
                               pin_error=True,
                               language=session["language"])
    return redirect(redirect_url)


def get_browser_lang():
    return request.accept_languages.best_match(['sv', 'en'])


def change_language():
    if "language" not in session:
        session["language"] = get_browser_lang()
    if ("lang" in request.form):
        session["language"] = request.form["lang"]
        return True
    return False
