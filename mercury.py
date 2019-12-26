#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import base64
import json
import logging
import sys
from urllib.parse import unquote, urljoin

import requests
import rsa
from ptpython.repl import embed


LOG_FORMAT = "%(levelname)-8s %(funcName)-12s %(message)s"
LOG_LEVEL = logging.DEBUG


class MercuryIPC:
    """
    Class for Mercury IPC Operations
    """
    _log = logging.getLogger(__name__)
    _log.setLevel(LOG_LEVEL)

    def __init__(self, url, username=None, password=None, token=None):
        self._s = requests.Session()
        self._url = url
        self._username = username
        self._password = password
        self._token = token

        if self._username and self._password:
            self.login()

    def send_request(self, body, token=None):
        if token:
            self._token = token
        self._log.debug(f"Sending request: {body}")
        resp = self._s.post(urljoin(self._url, f"/stok={self._token}/ds"), json=body)
        self._log.debug(f"Response: {resp.status_code} {resp.json()}")

        return resp

    def login(self, username=None, password=None):
        if username:
            self._username = username
        if password:
            self._password = password
        assert self._username and self._password, "Please provide username and password"

        self._log.info("Retrive RSA Pubkey and Nonce")
        resp = self._s.post(self._url, json=self.PAYLOAD_LOGIN)
        self._log.debug(f"Response: {resp.status_code} {resp.json()}")
        data = resp.json()["data"]
        pubkey = unquote(data["key"])
        nonce = data["nonce"]

        # RSA encrypt
        # ref https://www.cnblogs.com/masako/p/7660418.html
        pubkey = base64.b64decode(pubkey)
        modulus = int.from_bytes(pubkey[29:29+128], 'big')
        exponent = int.from_bytes(pubkey[159:159+3], 'big')
        rsa_pubkey = rsa.PublicKey(modulus, exponent)
        crypto = rsa.encrypt(self.tp_encrypt(self._password, nonce).encode(), rsa_pubkey)
        password_encrypted = base64.b64encode(crypto).decode()
        self._log.debug(f"Encrypted password: {password_encrypted}")

        payload = self.PAYLOAD_LOGIN
        payload["login"]["username"] = self._username
        payload["login"]["password"] = password_encrypted

        self._log.info(f"Login with username [{self._username}]")
        resp = self._s.post(self._url, json=payload)
        self._log.debug(f"Login response: {resp.status_code} {resp.json()}")
        self._token = resp.json()["stok"]
        return self._token

    def isLoggedIn(self):
        if not self._token:
            return False
        resp = self.send_request(self.PAYLOAD_GET_BASIC_INFO)
        self._log.debug(f"isLoggedIn basic_info response: {resp.status_code} {resp.text}")
        if resp.status_code != 200 or resp.json()["error_code"] < 0:
            self._log.info("isLoggedIn check failed")
            return False
        return True

    def ensureLoggedIn(self):
        if not self.isLoggedIn():
            self.login()

    # ref https://github.com/gyje/tplink_encrypt/blob/9d93c2853169038e25f4e99ba6c4c7b833d5957f/tpencrypt.py
    @staticmethod
    def tp_encrypt(password, nonce):
        a = 'RDpbLfCPsJZ7fiv'
        c = 'yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW '
        b = password
        e = ''
        f, g, h, k, l = 187, 187, 187, 187, 187
        n = 187
        g = len(a)
        h = len(b)
        k = len(c)
        if g > h:
            f = g
        else:
            f = h
        for p in list(range(0, f)):
            n = l = 187
            if p >= g:
                n = ord(b[p])
            else:
                if p >= h:
                    l = ord(a[p])
                else:
                    l = ord(a[p])
                    n = ord(b[p])
            e += c[(l ^ n) % k]
        return f"{e}:{nonce}"

    # Login
    PAYLOAD_LOGIN = {"method":"do","login":{"username":"admin","encrypt_type":"2","password":"no_password"}}

    # Get informations
    PAYLOAD_GET_BASIC_INFO = {"method":"get","device_info":{"name":["basic_info"]}}
    PAYLOAD_GET_UNKNOWN = {"method":"get","cet":{"name":["vhttpd"]}}

    # Len Mask
    PAYLOAD_SET_LENMASK_ON = {"method":"set","lens_mask":{"lens_mask_info":{"enabled":"on"}}}
    PAYLOAD_SET_LENMASK_OFF = {"method":"set","lens_mask":{"lens_mask_info":{"enabled":"off"}}}

    # PTZ Presets
    PAYLOAD_GET_PRESET = {"method":"get","preset":{"name":["preset"]}}
    PAYLOAD_SET_PRESET = {"method":"do","preset":{"set_preset":{"name":"name","save_ptz":"1"}}}
    PAYLOAD_GOTO_PRESET = {"method":"do","preset":{"goto_preset": {"id": "1"}}}

    # PTZ Motors
    PAYLOAD_DO_MOTOR_LEFT = {"method":"do","motor":{"move":{"x_coord":"10","y_coord":"0"}}}


if __name__ == "__main__":
    logging.basicConfig(format=LOG_FORMAT)
    log = logging.getLogger("main")
    log.setLevel(LOG_LEVEL)

    mer = MercuryIPC("http://192.168.1.100", "username", "password")
    log.debug(mer)

    log.info("Mercury IPC is available at variable [mer], fire at will ;p")

    embed(globals(), locals(), title="Mercury IPC Control")
