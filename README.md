# ALservice

A webservice for linking multiple accounts at identity providers to a single email address (provided
 by the end-user).

![](images/ALservice.png "Account linking service overview")

1. Proxy send a request and some parameters; The IdP at which the user authenticated, a user_id 
and a redirect endpoint. The parameters are packed as a signed JWT.
1. Return response to proxy
    1. If a unique identifier exists it is returned to the proxy 
    1. If no unique identifier exists then a ticket is generated and returned
1. If a ticket where returned then a new request containing the ticket is sent. Else flow is complete!
1. Shows log in screen 
    1. If user has no account a token is generated and sent to a email registered by the user
    1. User enter token received in the email and chooses a pin code an creates an account
1. User enters email and pin which are validated
1. A link between the IdpP and user are created
1. An unique identifier is generated and stored by the Account linking service are returned to the 
proxy

# Install dependencies
To install all necessary dependencies, run `python setup.py install` in the root directory.


# Run ALservice 
Copy the **settings.cfg.example** and rename the copy **settings.cfg**. If needed modify the 
necessary configurations. 

Copy the **message.txt.example** and rename to whatever you want, for example **message.txt**. 
If you name the file anything other than **message.txt** please update the MESSAGE_TEMPLATE attribute
in the **settings.cfg** file.

```shell
export ALSERVICE_CONFIG=<path to settings.cfg> gunicorn alservice.service.run:app
```

Make sure to setup HTTPS cert and key, and bind to the correct host/port using
[gunicorn settings](http://docs.gunicorn.org/en/latest/settings.html).

# Configuration
| Parameter name | Data type | Example value | Description |
| -------------- | --------- | ------------- | ----------- |
| SSL | boolean | True | Should the server use https or not |
| SERVER_CERT | String | "./keys/server.crt" | The path to the certificate file used by SSL comunication |
| SERVER_KEY | String | "./keys/server.key" | The path to the key file used by SSL comunication |
| JWT_PUB_KEY | List of strings | ["./keys/satosa.pub"] | A list of signature verification keys |
| SECRET_SESSION_KEY | String | "t3ijtgglok432jtgerfd" | A random value used by cryptographic components to for example to sign the session cookie |
| PORT | Integer | 8167 | Port on which the ALservice should start if running the dev server in `run.py` |
| HOST | String | "127.0.0.1" | The IP-address on which the ALservice should run if running the dev server in `run.py` |
| DEBUG | boolean | False | Turn on or off the Flask servers internal debugging, should be turned off to ensure that all log information get stored in the log file |
| DATABASE_URL | String | "mysql://localhost:3306/test" | URL to SQLite/MySQL/Postgres database, if not supplied an in-memory SQLite database will be used |
| AUTO_SELECT_ATTRIBUTES | boolean | True | Specifies if all the attributes in the GUI should be selected or not |
| MAX_CONSENT_EXPIRATION_MONTH | Integer | 12 | The maximum numbers of months a consent could be valid |
| USER_CONSENT_EXPIRATION_MONTH | List of integers | [3, 6] | A list of alternatives for how many months a user wants to give consent |
| LOG_FILE | String | "server.log" | A path to the log file, if none exists it will be created |
| LOG_LEVEL | String | "WARNING" | Which logging level the application should use. Possible values: INFO, DEBUG, WARNING, ERROR and CRITICAL |
| MESSAGE_TEMPLATE | String | "message.txt" | This is a path to the email message template file |
| MESSAGE_FROM | String | "al.service@umu.se" | Email sender address which is used in email verification email |
| MESSAGE_SUBJECT | String | "Account registration" | Email verification message subject  |
| SMTP_SERVER | String | "smtp.umu.se" | SMTP server to use when sending email |
| SALT | String | "fg9024jk5rmfdsvp0upASDIOPUmfadsf0qw3" | Salt is used when hash different values |
| PIN_CHECK | String | "((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})" | Regular expression which the pin codes needs to follow |
| PIN_EMPTY | boolean | True | If true the user does not need to enter a pin at registration |


# Storage
Some information has to be stored in order for the CMservice to work

## Database alternatives
Currently the consent could be stored in either in memory database or in a  SQLite database. 
Please read the "Configuration" section for more information on how to switch between the 
different database instances.

## Stored information 
First of there are information about the ticket like the ticket it self, when it was created and 
for whom, a hash value from IdP and user_id and a redirect url back to the client.

Then there are information about token used when creating an account and verifying an email address.
Besides the token it self a timestamp for when the token where created and the users email is stored.

The database also contains information about the account. This information consists of an email, an 
timestamp, a pin code and a unique identifier for that particular user.


# Development

## i18n

To extract all i18n string:

```bash
python setup.py extract_messages --input-paths src/alservice/ --output-file src/alservice/service/data/i18n/messages.pot
```

To compile .po->.mo:

```bash
python setup.py compile_catalog --directory src/alservice/service/data/i18n/locales/
```


See [Babel docs](http://babel.pocoo.org/en/latest/setup.html) for more info.