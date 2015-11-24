<%inherit file="base.mako"/>

<%block name="head_title">Account linking service</%block>
<%block name="page_header">${_("Create account")}</%block>

<p>${_("Token was sent to: ")} ${ email }</p>