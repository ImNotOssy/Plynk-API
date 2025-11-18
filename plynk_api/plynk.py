import json
import logging
import os
import pickle
import pytz

from datetime import datetime
from curl_cffi import requests
from typing import Optional, Callable

try:
    from . import endpoints
except Exception:
    # Fallback for environments where package-relative imports aren't available:
    import importlib
    endpoints = importlib.import_module("endpoints")



def check_login(func):
    def wrapper(self, *args, **kwargs):
        if not self.logged_in:
            raise RuntimeError("Plynk not logged in. Please login first.")
        return func(self, *args, **kwargs)
    return wrapper


class Plynk:
    def __init__(self, username: str, password: str, filename: str = "plynk_credentials.pkl", path: Optional[str] = None, proxy_url: Optional[str] = None, proxy_auth: Optional[tuple[str, str]] = None, debug: bool = False):
        self.username: str = username
        self.password: str = password
        self.filename: str = filename
        self.path: Optional[str] = path
        self.proxy_url: Optional[str] = proxy_url
        self.proxy_auth: Optional[tuple[str, str]] = proxy_auth
        # --- CHANGE: Store debug flag ---
        self.debug: bool = debug
        if self.debug:
            logging.info("Initializing Plynk client in DEBUG mode.")

        self._set_session(proxy_url, proxy_auth)
        self.account_number: Optional[str] = None
        self.logged_in: bool = False
        self._load_credentials()

    def _set_session(self, proxy_url: str, proxy_auth: Optional[tuple[str, str]] = None) -> None:
        if self.debug:
            logging.info("Setting up new request session.")
        self.session: requests.Session = requests.Session(impersonate="safari_ios", timeout=10)
        if proxy_url:
            self.session.proxies = {"http": proxy_url, "https": proxy_url}
            if proxy_auth:
                self.session.proxy_auth = proxy_auth

    def _load_credentials(self) -> None:
        filename = os.path.join(self.path or '.', self.filename)
        if self.debug:
            logging.info(f"Attempting to load credentials from: {filename}")
        if os.path.exists(filename):
            try:
                with open(filename, "rb") as f:
                    credentials = pickle.load(f)
                    self.session.cookies.jar._cookies.update(credentials.get("cookies", {}))
                if self.debug:
                    logging.info("Successfully loaded credentials from file.")
            except Exception as e:
                logging.error(f"Failed to load or parse credentials file: {e}")
        elif self.debug:
            logging.warning("Credential file not found.")

    def _save_credentials(self) -> None:
        filename = os.path.join(self.path or '.', self.filename)
        if self.path and not os.path.exists(self.path):
            os.makedirs(self.path)
        if self.debug:
            logging.info(f"Saving credentials to: {filename}")
        with open(filename, "wb") as f:
            credentials_to_save = {"cookies": self.session.cookies.jar._cookies}
            pickle.dump(credentials_to_save, f)
        if self.debug:
            logging.info("Credentials saved successfully.")

    def _clear_credentials(self) -> None:
        if self.debug:
            logging.warning("Clearing credentials and session.")
        filename = os.path.join(self.path or '.', self.filename)
        if os.path.exists(filename):
            os.remove(filename)
        self._set_session(self.proxy_url, self.proxy_auth)

    def login(self, otp_callback: Optional[Callable[[], str]] = None) -> bool:
        if self.debug:
            logging.info("Starting login process.")
        
        if self.debug:
            logging.info("Step 1: Verifying existing session...")
        if self._verify_login():
            self.logged_in = True
            if self.debug:
                logging.info("Existing session is valid.")
            self.account_number = self._fetch_account_number()
            if self.debug:
                logging.info("Login successful (using existing session).")
            return True
        
        if self.debug:
            logging.warning("Existing session is invalid. Starting fresh login.")
        self._clear_credentials()

        if self.debug:
            logging.info("Step 2: Authenticating with username and password...")
        self.session.post(
            endpoints.authentication_url(),
            json={"username": self.username, "requestBaseInfo": None, "password": self.password},
            headers=endpoints.build_headers(domain='ecaap')
        ).raise_for_status()
        if self.debug:
            logging.info("Password authentication successful.")

        if self.debug:
            logging.info("Step 3: Polling for session status...")
        poll_response = self.session.post(
            endpoints.login_url(),
            json={},
            headers=endpoints.build_headers(domain='ecaap', login_poll=True)
        )
        poll_response.raise_for_status()
        poll_data = poll_response.json()
        if self.debug:
            logging.info(f"Session poll response: {poll_data}")
        
        session_status = poll_data.get("responseBaseInfo", {}).get("status", {}).get("message", "")
        
        if session_status == "Authentication Not Completed":
            if self.debug:
                logging.info("OTP is required.")
            raise NotImplementedError("OTP flow is defined but needs to be triggered to be tested.")
        
        if session_status != "Session Created":
            raise RuntimeError(f"Login failed with unexpected status: {session_status}")

        if self.debug:
            logging.info("Session created successfully!")
        self.logged_in = True
        self.account_number = self._fetch_account_number()
        self._save_credentials()
        if self.debug:
            logging.info("Login process completed successfully.")
        return True

    def _fetch_account_number(self) -> str:
        if self.debug:
            logging.info("Fetching account details to find account number.")
        response = self.session.get(
            endpoints.details_url(),
            headers=endpoints.build_headers(domain='digital')
        )
        response.raise_for_status()
        data = response.json()
        
        try:
            account_num = data['user']['customer']['accounts'][0]['accountNumber']
            if self.debug:
                logging.info(f"Successfully fetched account number: {account_num}")
            return account_num
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Could not parse account number from details response: {e}")

    def _verify_login(self) -> bool:
        if self.debug:
            logging.info("Verifying login status by checking account details endpoint.")
        try:
            response = self.session.get(
                endpoints.details_url(), 
                headers=endpoints.build_headers(domain='digital'),
                timeout=5
            )
            if self.debug:
                logging.info(f"Verification response status code: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            logging.error(f"An exception occurred during login verification: {e}")
            return False

    @check_login
    def get_account_total(self, account_number: str) -> float:
        payload = {"accounts": [{"accountNumber": f"{account_number}", "registrationType": "I"}]}
        response = self.session.post(endpoints.balance_url(), json=payload, headers=endpoints.build_headers(domain='digital'))
        response.raise_for_status()
        response_json = response.json()
        if "accounts" in response_json and response_json["accounts"]:
            try:
                return float(response_json["accounts"][0]["balanceSummary"]["totalAssets"])
            except (KeyError, ValueError, IndexError):
                raise RuntimeError("Unable to parse account total value.")
        return 0.0

    @check_login
    def get_positions(self, account_number: str) -> dict:
        payload = {"accounts": [{"accountNumber": f"{account_number}", "registrationType": "I"}]}
        response = self.session.post(endpoints.positions_url(), json=payload, headers=endpoints.build_headers(domain='digital'))
        response.raise_for_status()
        return response.json()

    @check_login
    def get_account_holdings(self, account_number: str) -> list:
        result = self.get_positions(account_number)
        return result["accounts"][0].get("positionsSummary", {}).get("positions", [])
        
    @check_login
    def get_stock_price(self, ticker: str) -> float:
        response = self.get_stock_details(ticker)
        try:
            return float(response["securityDetails"]["lastPrice"])
        except (KeyError, ValueError):
            raise RuntimeError("Unable to get float value for stock price.")

    @check_login
    def get_stock_details(self, ticker: str) -> dict:
        querystring = {"quoteType": "R", "symbol": ticker, "proIndicator": "N", "contextLevel": "2"}
        response = self.session.get(endpoints.stock_details_url(), headers=endpoints.build_headers(domain='digital'), params=querystring)
        response.raise_for_status()
        return response.json()
