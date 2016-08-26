import logging
from urllib.parse import parse_qsl

import jwkest
from flask.blueprints import Blueprint
from flask.globals import current_app, session, request
from flask_mako import render_template
from jwkest import jws
from werkzeug.exceptions import abort
from werkzeug.utils import redirect

from alservice.al import IdRequest
from alservice.exception import ALserviceNoSuchKey, ALserviceAuthenticationError, ALserviceTokenError, \
    ALserviceTicketError, ALserviceNotAValidPin

logger = logging.getLogger(__name__)

account_linking_views = Blueprint('account_linking_service', __name__, url_prefix='')


@account_linking_views.route("/get_id")
def get_id():
    parsed_qs = dict(parse_qsl(request.query_string.decode()))
    try:
        jwt = parsed_qs["jwt"]
    except KeyError:
        abort(400)

    try:
        params = jws.factory(jwt).verify_compact(jwt, current_app.al.trusted_keys)
    except jwkest.Invalid as e:
        logger.debug("received invalid id request: %s", jwt)
        abort(400)

    try:
        data = IdRequest(params)
    except ValueError:
        logger.debug("received invalid id request: %s", params)
        abort(400)

    try:
        uuid = current_app.al.get_uuid(data.key)
        return uuid, 200
    except ALserviceNoSuchKey:
        logger.debug("no key found for request: ", data)
        ticket = current_app.al.create_ticket(data)
        return ticket, 404


@account_linking_views.route("/approve/<ticket>", methods=["POST", "GET"])
def approve(ticket):
    template_params = dict(form_action='/approve/%s' % ticket, ticket=ticket, login_failed_message=False)

    if not change_language():
        session["ticket"] = ticket

        # user has approved linking
        if request.method == "POST":
            email = request.form["email"]
            pin = request.form["pin"]
            redirect_url = current_app.al.get_redirect_url(ticket)
            try:
                current_app.al.link_key(email, pin, ticket)
                return redirect(redirect_url)
            except ALserviceAuthenticationError:
                template_params["login_failed_message"] = True

    template_params["language"] = session["language"]
    return render_template("login.mako", **template_params)


@account_linking_views.route("/create_account", methods=["POST"])
def create_account():
    change_language()
    return render_template("create_account.mako",
                           form_action="/create_account",
                           language=session["language"])


@account_linking_views.route("/send_token", methods=["POST"])
def send_token():
    if not change_language():
        email = request.form.get("email", session.get("email"))
        ticket = session.get("ticket")
        if not email or not ticket:
            abort(400)

        session["email"] = email
        current_app.al.create_account_step1(email, ticket)

    return render_template("token_was_sent.mako",
                           form_action="/send_token",
                           email=session["email"],
                           token_error=False,
                           language=session["language"])


@account_linking_views.route("/verify_token", methods=["POST"])
def verify_token():
    if not change_language():
        token = request.form.get("token", session.get("token"))
        if not token:
            abort(400)

        session["token"] = token
        try:
            current_app.al.create_account_step2(token)
        except (ALserviceTokenError, ALserviceTicketError):
            return render_template("token_was_sent.mako",
                                   form_action='/verify_token',
                                   email=session["email"],
                                   token_error=True,
                                   language=session["language"])

    return render_template("save_account.mako",
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
                               form_action='/verify_token',
                               pin_error=True,
                               language=session["language"])
    return redirect(redirect_url)


def get_browser_lang():
    return request.accept_languages.best_match(['sv', 'en'])


def change_language():
    if "language" not in session:
        session["language"] = get_browser_lang()
    if "lang" in request.form:
        session["language"] = request.form["lang"]
        return True
    return False
