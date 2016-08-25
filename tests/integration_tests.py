import json

import pytest
import requests
from flask.helpers import url_for
from jwkest.jws import JWS
from selenium import webdriver
from selenium.webdriver.support.select import Select


@pytest.yield_fixture
def selenium_driver():
    driver = webdriver.PhantomJS()
    yield driver
    driver.close()


@pytest.mark.usefixtures("live_server")
class TestService:
    def _make_get_id_request(self, signing_key, id="test_id", idp="test-idp"):
        data = {
            "id": id,
            "idp": idp,
            "redirect_endpoint": "https://client.example.com/redirect"
        }
        jws = JWS(json.dumps(data), alg=signing_key.alg).sign_compact([signing_key])

        account_linking_url = url_for("account_linking_service.get_id", jwt=jws, _external=True)
        resp = requests.get(account_linking_url)

        return resp

    def create_ticket(self, signing_key, id="test_id", idp="test-idp"):
        resp = self._make_get_id_request(signing_key, id, idp)
        assert resp.status_code == 404

        ticket = resp.text
        return ticket

    def get_linked_id(self, signing_key, id="test_id", idp="test-idp"):
        resp = self._make_get_id_request(signing_key, id, idp)
        assert resp.status_code == 200

        id = resp.text
        return id

    def create_account(self, selenium_driver, email, pin):
        selenium_driver.find_element_by_id("create_button").click()
        selenium_driver.find_element_by_xpath("//input[@name='email']").send_keys(email)
        selenium_driver.find_element_by_id("send_token_button").click()

        # get the created token from the file created by TestEmail (instead of actually sending it by email)
        with open("token") as f:
            token = f.read()
        assert token
        selenium_driver.find_element_by_xpath("//input[@name='token']").send_keys(token)
        selenium_driver.find_element_by_id("verify_button").click()

        # save account with pin code
        selenium_driver.find_element_by_xpath("//input[@name='pin']").send_keys(pin)
        selenium_driver.find_element_by_id("save_button").click()

    def link_with_existing_account(self, selenium_driver, email, pin):
        selenium_driver.find_element_by_xpath("//input[@name='email']").send_keys(email)
        selenium_driver.find_element_by_xpath("//input[@name='pin']").send_keys(pin)
        selenium_driver.find_element_by_id("approve_button").click()

    def test_full_flow(self, signing_key, selenium_driver):
        # create account linking request
        ticket = self.create_ticket(signing_key)

        # redirect user to the page
        approve_linking_url = url_for("account_linking_service.approve", ticket=ticket, _external=True)
        selenium_driver.get(approve_linking_url)

        self.create_account(selenium_driver, "test_user@example.com", "!AbC123#")
        assert self.get_linked_id(signing_key)

    def test_existing_account(self, signing_key, selenium_driver):
        email = "test_user@example.com"
        pin = "!AbC123#"
        # create account linking request
        ticket = self.create_ticket(signing_key, "my_id", "idp1")

        # redirect user to the page
        approve_linking_url = url_for("account_linking_service.approve", ticket=ticket, _external=True)
        selenium_driver.get(approve_linking_url)

        self.create_account(selenium_driver, email, pin)

        # create new account linking request
        ticket = self.create_ticket(signing_key, "other_id", "idp2")
        # redirect user to the page
        approve_linking_url = url_for("account_linking_service.approve", ticket=ticket, _external=True)
        selenium_driver.get(approve_linking_url)

        self.link_with_existing_account(selenium_driver, email, pin)
        assert self.get_linked_id(signing_key, "my_id", "idp1") == self.get_linked_id(signing_key, "other_id", "idp2")

    def test_language_change(self, signing_key, selenium_driver):
        ticket = self.create_ticket(signing_key)
        approve_linking_url = url_for('account_linking_service.approve', ticket=ticket, _external=True)
        selenium_driver.get(approve_linking_url)

        # switch language: english
        select = Select(selenium_driver.find_element_by_id("lang"))
        select.options[0].click()
        page_heading = selenium_driver.find_element_by_xpath('//h1')
        assert "Account linking" in page_heading.text

        # switch language: swedish
        select = Select(selenium_driver.find_element_by_id("lang"))
        select.options[1].click()
        page_heading = selenium_driver.find_element_by_xpath('//h1')
        assert "Kontolänkning" in page_heading.text
