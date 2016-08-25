<%inherit file="base.mako"/>

<%block name="head_title">Account linking service</%block>
<%block name="page_header">${_("Create account")}</%block>

<form class="form-horizontal" role="form" name="send_token" action="/send_token" method="POST">
    <input type="text" class="form-control" placeholder=${_("Email")} name="email">
    <button name="send" id="send_token_button" class="btn btn-primary" type="submit">${_('Send token')}</button>
</form>
