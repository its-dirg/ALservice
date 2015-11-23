<%!
    import json
    def to_json(d):
        return json.dumps(d, indent=0)
%>

<!DOCTYPE html>

<html>
<head>
    <title><%block name="head_title"></%block></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="content-type" content="text/html;" charset="utf-8"/>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
    <link rel="stylesheet" href="/static/style.css">

    <!-- Latest compiled and minified JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"
            integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ=="
            crossorigin="anonymous"></script>
</head>
<body>

<div class="container">
    <!-- Main jumbotron for a primary marketing message or call to action -->
    <div class="jumbotron">
        <h1>${_("Account linking service")}</h1>
        <p>${_("Links your accounts!")}</p>
       <!-- Language selection -->
        <div class="col-md-1">
            <form action="${form_action}" method="POST">
                <select name="lang" id="lang" onchange="this.form.submit()" class="dropdown-menu-right">
                    <option value="en">EN</option>
                    <option value="sv">SV</option>
                </select>
                <%block name="extra_inputs"></%block>
            </form>
        </div>
    </div>

    <div class="page-header">
            <h2><%block name="page_header"></%block></h2>
          </div>
    </div>

    <div class="container">
        ${self.body()}
    </div>
</div>

<script type="application/javascript">
    "use strict";

    // Mark the selected language in the dropdown
    var lang = "${language}";
    var lang_option = document.querySelector("option[value=" + lang + "]");
    lang_option.selected = true;
</script>

</body>
</html>