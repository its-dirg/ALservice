<%inherit file="base.mako"/>

<%block name="head_title">Account linking service</%block>
<%block name="page_header">${_("Account linking")}</%block>

<form class="form-horizontal" role="form" name="create_account" action="/save_account" method="POST">
    <input type="password" class="form-control" placeholder=${_("PIN")} name="pin">
    <button name="save" id="save_button" class="btn btn-default" type="submit">${_('save and approve')}</button>
</form>
