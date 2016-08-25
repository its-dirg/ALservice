<%inherit file="base.mako"/>

<%block name="head_title">Account linking service</%block>
<%block name="page_header">${_("Account linking")}</%block>

% if pin_error:
    <div class="alert alert-danger" role="alert">
        <p>${_("PIN_ERROR_MESSAGE")}</p>
    </div>
% endif

<form class="form-horizontal" role="form" name="create_account" action="/save_account" method="POST">
    <input type="password" class="form-control" placeholder=${_("PIN")} name="pin">
    <button name="save" id="save_button" class="btn btn-default" type="submit">${_('Save and approve')}</button>
</form>
