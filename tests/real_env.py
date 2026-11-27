"""Test helper: a real PKI home with users made through the real flows
(ca.init_pki -> accounts.signup -> ca.approve -> accounts.login).

Passphrases are generated at random on each run: none is written in the code.
"""
import secrets
from pathlib import Path

from ping import accounts, ca


class RealEnv:
    def __init__(self, home):
        self.home = Path(home)
        self.ROOT_PASS = secrets.token_urlsafe(16)
        self.SUB_PASS = secrets.token_urlsafe(16)
        self.PASSWORD = secrets.token_urlsafe(16)   # one password for every test user
        self.root_fp = ca.init_pki(self.home, self.ROOT_PASS, self.SUB_PASS)

    def signup(self, name, password=None):
        accounts.signup(self.home, name, password or self.PASSWORD, lambda fp: fp == self.root_fp)

    def add_user(self, name, password=None):
        """Sign up, approve and log in: returns the user's keystore.Session."""
        self.signup(name, password)
        ca.approve(self.home, name, self.SUB_PASS)
        return accounts.login(self.home, name, password or self.PASSWORD)
