<%inherit file="base.mako"/>

<%block name="head_title">Account linking service</%block>
<%block name="page_header">${_("Create account")}</%block>

<p>${_("Token was sent to: ")} ${ email }</p>

% if token_error:
    <div class="alert alert-danger" role="alert">
        <p>${_("TOKEN_ERROR")}</p>
    </div>
% endif

<form class="form-horizontal" role="form" name="create_account" action="/verify_token" method="POST">
    <input type="text" class="form-control" placeholder=${_("Token")} name="token">
    <button name="verify" id="verify_button" class="btn btn-default" type="submit">${_('Verify token')}</button>
</form>
