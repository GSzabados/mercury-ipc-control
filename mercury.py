#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import base64
import logging
import sys
from ast import literal_eval
from urllib.parse import unquote, urljoin

import requests
import rsa
from ptpython.repl import embed


LOG_FORMAT = "%(levelname)-8s %(funcName)-12s %(message)s"
LOG_LEVEL = logging.INFO


class MercuryIPC:
    """
    Class for Mercury IPC Operations
    """

    def __init__(self, urlcfg, username=None, password=None, token=None):
        self._log = logging.getLogger(__name__)
        self._log.setLevel(LOG_LEVEL)
        self._s = requests.Session()
        # if dict: configs
        if isinstance(urlcfg, dict):
            self._url = urlcfg["url"]
            self._username = urlcfg["username"]
            self._password = urlcfg["password"]
            self._token = urlcfg.get('token')
            # self.ensureLoggedIn()
        else:
            self._url = urlcfg
            self._username = username
            self._password = password
            self._token = token

            if self._username and self._password:
                self.ensureLoggedIn()

    def sendRequest(self, body, token=None):
        if token:
            self._token = token
        while True:
            self._log.info(f"Sending request: {body}")
            resp = self._s.post(urljoin(self._url, f"/stok={self._token}/ds"), json=body)
            data = resp.json()

            if data["error_code"] == -40401 and "key" in data["data"]:
                self._log.warning("Login token expired, re-logging in...")
                self.login(previous_resp=resp)
                self._log.info("Retrying previous request...")
            else:
                if data["error_code"] == 0:
                    self._log.debug(f"Response: {resp.status_code} {data}")
                elif data["error_code"] == -64324:
                    self._log.error(f"Camera is OFF, Maybe LENSMASK is enabled")
                else:
                    self._log.error(f"Request Failed: {resp.status_code} {data}")
                break

        return resp

    def login(self, username=None, password=None, previous_resp=None):
        if username:
            self._username = username
        if password:
            self._password = password
        assert self._username and self._password, "Please provide username and password"

        if previous_resp is None:
            self._log.info("Retrive RSA Pubkey and Nonce")
            resp = self._s.post(self._url, json=self.PAYLOAD_LOGIN)
            self._log.debug(f"Response: {resp.status_code} {resp.json()}")
        else:
            self._log.info("Extracting Pubkey and Nonce from previous response.")
            resp = previous_resp
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
        resp = self.sendRequest(self.PAYLOAD_GET_BASIC_INFO)
        self._log.debug(f"isLoggedIn basic_info response: {resp.status_code} {resp.text}")
        if resp.status_code != 200 or resp.json()["error_code"] < 0:
            self._log.info("isLoggedIn check failed")
            return False
        return True

    def ensureLoggedIn(self):
        if not self.isLoggedIn():
            self.login()

    def export(self):
        return {
            "url": self._url,
            "username": self._username,
            "password": self._password,
            "token": self._token,
        }

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

    # === Login
    PAYLOAD_LOGIN = {"method":"do","login":{"username":"admin","encrypt_type":"2","password":"no_password"}}

    # ===  Get informations
    PAYLOAD_GET_BASIC_INFO = {"method":"get","device_info":{"name":["basic_info"]}}
    PAYLOAD_GET_MODULE_SPEC = {"method":"get","function":{"name":["module_spec"]}}
    PAYLOAD_GET_CAPABILITIES = {"method":"get","audio_capability":{"name":["device_speaker","device_microphone"]},"motor":{"name":["capability"]},"playback":{"table":["scale_capability"]},"cet":{"name":["media_encrypt"]}}
    PAYLOAD_GET_HARDDISK = {"method":"get","harddisk_manage":{"table":["hd_info"],"name":["harddisk"]}}
    PAYLOAD_GET_NETWORK_TYPE = {"method":"do","network":{"get_connection_type":"null"}}
    PAYLOAD_GET_CLOCK_STATUS = {"method":"get","system":{"name":["clock_status"]}}
    PAYLOAD_GET_UNKNOWN = {"method":"get","cet":{"name":["vhttpd"]}}

    # === LED
    PAYLOAD_SET_LED_ON = {"method":"set","led":{"config":{"enabled":"on"}}}
    PAYLOAD_SET_LED_OFF = {"method":"set","led":{"config":{"enabled":"off"}}}

    # === object track
    PAYLOAD_SET_TRACK_ON = {"method":"set","target_track":{"target_track_info":{"enabled":"on"}}}
    PAYLOAD_SET_TRACK_OFF = {"method":"set","target_track":{"target_track_info":{"enabled":"off"}}}

    # === Alarm
    PAYLOAD_SET_ALARM_ON ={"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}
    PAYLOAD_SET_ALARM_OFF = {"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"stop"}}}

    # === Lens Mask
    PAYLOAD_GET_LENSMASK_INFO = {"method":"get","lens_mask":{"name":["lens_mask_info"]}}
    # Response: { "lens_mask": { "lens_mask_info": { ".name": "lens_mask_info", ".type": "lens_mask_info", "enabled": "on" } }, "error_code": 0 }
    PAYLOAD_SET_LENSMASK_ON = {"method":"set","lens_mask":{"lens_mask_info":{"enabled":"on"}}}
    PAYLOAD_SET_LENSMASK_OFF = {"method":"set","lens_mask":{"lens_mask_info":{"enabled":"off"}}}

    # === PTZ Presets
    PAYLOAD_GET_PRESET = {"method":"get","preset":{"name":["preset"]}}
    PAYLOAD_SET_PRESET = {"method":"do","preset":{"set_preset":{"name":"CHANGEME","save_ptz":"1"}}}
    # Response: {'id': '6', 'name': 'DEFAULT', 'error_code': 0
    PAYLOAD_GOTO_PRESET = {"method":"do","preset":{"goto_preset": {"id": "1"}}}
    PAYLOAD_DELETE_PRESET = {"method":"do","preset":{"remove_preset":{"id":["CHANGEME"]}}}

    # === PTZ Motors
    PAYLOAD_DO_MOTOR_STOP = {"method":"do","motor":{"stop":"null"}}
    # Step: post per 0.5s
    PAYLOAD_DO_MOTOR_STEP_LEFT = {"method":"do","motor":{"movestep":{"direction":"180"}}}
    PAYLOAD_DO_MOTOR_STEP_RIGHT = {"method":"do","motor":{"movestep":{"direction":"0"}}}
    PAYLOAD_DO_MOTOR_STEP_UP = {"method":"do","motor":{"movestep":{"direction":"90"}}}
    PAYLOAD_DO_MOTOR_STEP_UP = {"method":"do","motor":{"movestep":{"direction":"270"}}}
    # Move: relative movement
    PAYLOAD_DO_MOTOR_MOVE = {"method":"do","motor":{"move":{"x_coord":"CHANGEME","y_coord":"CHANGEME"}}}
    PAYLOAD_DO_MOTOR_MOVE_LEFT = {"method":"do","motor":{"move":{"x_coord":"-10","y_coord":"0"}}}
    PAYLOAD_DO_MOTOR_MOVE_RIGHT = {"method":"do","motor":{"move":{"x_coord":"10","y_coord":"0"}}}
    PAYLOAD_DO_MOTOR_MOVE_UP = {"method":"do","motor":{"move":{"x_coord":"0","y_coord":"10"}}}
    PAYLOAD_DO_MOTOR_MOVE_DOWN = {"method":"do","motor":{"move":{"x_coord":"0","y_coord":"-10"}}}


def main():
    import argparse
    from configparser import ConfigParser

    global LOG_LEVEL

    functions = ["interactive", "send", "presets", "goto", 'mask']

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-c", "--config", default="mercury.ini", help="config file to read IPC endpoints")
    parser.add_argument("-h", "--host", help="Camera web interface URL")
    parser.add_argument("-u", "--username", help="Camera admin username")
    parser.add_argument("-p", "--password", help="Camera admin password")
    parser.add_argument("-d", "--debug", action='store_true', help="Print additional debug logs")
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help="RT")
    parser.add_argument("camera", nargs='?', default='cmdline', help="Specify the Camera to use. default: cmdline")
    parser.add_argument("action", choices=functions, default="interactive", help="Functions to call")
    parser.add_argument("action_args", nargs=argparse.REMAINDER, help="Function arguments")

    args = parser.parse_args()
    config = ConfigParser()
    config.read(args.config)

    if args.debug:
        LOG_LEVEL = logging.DEBUG

    logging.basicConfig(format=LOG_FORMAT)
    log = logging.getLogger("main")
    log.setLevel(LOG_LEVEL)

    camcfgs = dict((sec, dict(config[sec])) for sec in config.sections())
    if args.host and args.username and args.password:
        camcfgs["cmdline"] = {"url": args.host, "username": args.username, "password": args.password}

    try:
        camcfg = camcfgs[args.camera]
    except KeyError:
        log.fatal(f"Didn't specify a valid IPCamera config")
        raise SystemExit

    cam = MercuryIPC(camcfg)

    log.debug(cam)

    cmd = args.action
    if cmd == "interactive":
        # 交互式命令行
        log.info("Mercury IPC is available at variable [cam], fire at will ;p")

        embed(globals(), locals(), title="Mercury IPC Control")

    elif cmd == "send":
        # 发送 JSON payload
        assert len(args.action_args) > 0, "[send] command require 1 argument: payload"
        payload = args.action_args[0]
        if payload.startswith('PAYLOAD_'):
            payload = getattr(cam, payload)
        else:
            payload = literal_eval(payload)
        resp = cam.sendRequest(payload)
        print(resp.json())

    elif cmd == "presets":
        info = cam.sendRequest(cam.PAYLOAD_GET_PRESET).json()["preset"]["preset"]
        printed = '\n'.join(f"{info['id'][i]:3s}{info['name'][i]:10s}"
                      for i in range(len(info['id'])))
        print(f"\nPresets: \n{printed}\n")

    elif cmd == "goto":
        # 跳转到指定 preset
        assert len(args.action_args) > 0, "[goto] command require 1 argument: preset"
        payload = cam.PAYLOAD_GOTO_PRESET
        arg = args.action_args[0]
        payload["preset"]["goto_preset"]["id"] = arg
        cam.sendRequest(payload)

    elif cmd == "mask":
        if len(args.action_args) > 0:
            # 设置镜头遮罩状态
            arg = args.action_args[0]
            cam.sendRequest(cam.PAYLOAD_SET_LENSMASK_OFF if arg == "off" else cam.PAYLOAD_SET_LENSMASK_ON)
        else:
            # 查询镜头遮罩状态
            resp = cam.sendRequest(cam.PAYLOAD_GET_LENSMASK_INFO)
            # lens_mask": { "lens_mask_info
            status = resp.json()["lens_mask"]["lens_mask_info"]["enabled"]
            log.info(f"Lens mask is {status.upper()}")

    else:
        raise NotImplementedError(f"Command {cmd} not yet implemented")


    log.info("Saving configs back")
    config[args.camera].update(cam.export())
    with open(args.config, "w") as f:
        config.write(f)

    log.info("Bye")


if __name__ == "__main__":
    main()