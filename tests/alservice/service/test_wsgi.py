import json

import pytest
from future.backports.urllib.parse import urlencode
from jwkest.jwk import RSAKey, rsa_load
from jwkest.jws import JWS


class TestWSGIApp:
    @pytest.fixture(autouse=True)
    def create_test_client(self, app, cert_and_key):
        self.app = app.test_client()
        self.signing_key = RSAKey(key=rsa_load(cert_and_key[1]), alg="RS256")

    def test_full_flow(self):
        # make account linking request
        request_args = {"id": "id", "idp": "idp", "redirect_endpoint": "https://client.example.com/redirect_endpoint"}
        jws = JWS(json.dumps(request_args)).sign_compact([self.signing_key])
        path_get_id = "/get_id?{}".format(urlencode({"jwt": jws}))
        resp = self.app.get(path_get_id)
        assert resp.status_code == 404
        ticket = resp.data.decode("utf-8")

        # user gets redirected to the account linking page
        resp = self.app.get("/approve/{}".format(ticket))
        assert resp.status_code == 200

        # redirect user to create an account page
        resp = self.app.post("/create_account")
        assert resp.status_code == 200

        # send token by email (faked by writing it to a file)
        resp = self.app.post("/send_token", data={"email": "test@example.com"})
        assert resp.status_code == 200

        # get token from file
        with open("token") as f:
            token = f.read()

        # verify token
        resp = self.app.post("/verify_token", data={"token": token})
        assert resp.status_code == 200

        # save account with a pin code
        resp = self.app.post("/save_account", data={"pin": "!AbC123#"})
        assert resp.status_code == 302
        assert resp.headers["Location"] == request_args["redirect_endpoint"]

        # get the id
        resp = self.app.get(path_get_id)
        assert resp.status_code == 200
        assert resp.data.decode("utf-8")
