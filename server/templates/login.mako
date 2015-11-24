<%inherit file="base.mako"/>

<%block name="head_title">Account linking service</%block>
<%block name="page_header">${_("Account linking")}</%block>

% if login_failed_message:
    <div class="alert alert-danger" role="alert">
        <p>${_("USER_PASSWORD_ERROR")}</p>
    </div>
% endif


<form class="form-horizontal" role="form" name="approve" action="/approve/${ ticket }" method="POST">
    <input type="text" class="form-control" placeholder=${_("Email")} name="email">
    <input type="password" class="form-control" placeholder=${_("PIN")} name="pin">
    <button name="approve" id="approve_button" class="btn btn-primary" type="submit">${_('Approve')}</button>
</form>
<form class="form-horizontal" role="form" name="create_account" action="/create_account" method="POST">
    <button name="create" id="create_button" class="btn btn-default" type="submit">${_('Create account')}</button>
</form>
