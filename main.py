import re
from functools import wraps
import math
import hashlib
import hmac
import time
import urllib.request
import urllib.parse
from urllib.error import HTTPError, URLError
import logging
import configparser
import argparse

logging.basicConfig(
    format="%(asctime)s.%(msecs)03d [%(filename)s:%(lineno)d] %(message)s",
    datefmt="## %Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def checkvars(varlist, errorinfo):
    """
    Decorator to check if variables are defined before running a function.
    """
    if isinstance(varlist, str):
        varlist = [varlist]

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            exist_status = [self._is_defined(var) for var in varlist]
            assert not any(status is False for status in exist_status), errorinfo
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


def infomanage(successinfo=None, errorinfo=None):
    """
    Decorator to log information at different stages of function execution.
    """

    def decorator(func):
        nonlocal successinfo, errorinfo
        successinfo = successinfo or f"Successfully called function {func.__name__}"
        errorinfo = errorinfo or f"Failed to call function {func.__name__}"

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                result = func(self, *args, **kwargs)
                logger.info(successinfo)
                return result
            except Exception:
                logger.error(errorinfo)
                raise

        return wrapper

    return decorator


class LoginManager:

    def __init__(
        self,
        n="200",
        vtype="1",
        acid="1",
        enc="srun_bx1",
        server_format="http://auth.nyist.edu.cn",
    ):
        # urls
        self.url_login_page = server_format + "/srun_portal_pc?ac_id=1&theme=pro"
        self.url_get_challenge_api = server_format + "/cgi-bin/get_challenge"
        self.url_login_api = server_format + "/cgi-bin/srun_portal"
        self.url_online_api = server_format + "/cgi-bin/rad_user_info"

        self.header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"
        }

        # static parameters
        self.n = n
        self.vtype = vtype
        self.ac_id = acid
        self.enc = enc
        self.online_info = None
        self.logout_info = "true"

        self._PADCHAR = "="
        self._ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

    def check_online(self):
        return self.get_check_responce()

    def login(self, username, password):
        self.username = username
        self.password = password

        if not self.check_online():
            self.get_ip()
            self.get_token()
            self.get_login_responce()
            self.check_online()

        logger.info("online Info: " + str(self.online_info))
        return self.online_info

    def logout(self, username):
        self.username = username
        if self.check_online():
            self.get_logout_responce()

        return self.logout_info

    def get_ip(self):
        logger.info("Step1: Get local ip returned from srun server.")
        self._get_login_page()
        self._resolve_ip_from_login_page()

    def get_token(self):
        logger.info("Step2: Get token by resolving challenge result.")
        self._get_challenge()
        self._resolve_token_from_challenge_response()

    def get_login_responce(self):
        logger.info("Step3: Loggin and resolve response.")
        self._generate_encrypted_login_info()
        self._send_login_info()
        self._resolve_login_responce()
        logger.info("The loggin result is: " + self._login_response_text)

    def get_logout_responce(self):
        self._send_logout_info()

    def get_check_responce(self):
        return self._send_check_info()

    def _is_defined(self, varname):
        """
        Check whether variable is defined in the object
        """
        allvars = vars(self)
        return varname in allvars

    @infomanage(
        successinfo="Successfully get login page",
        errorinfo="Failed to get login page, maybe the login page url is not correct",
    )
    def _get_login_page(self):
        req = urllib.request.Request(self.url_login_page, headers=self.header)
        with urllib.request.urlopen(req) as resp:
            self._page_response_text = resp.read().decode("utf-8")

    @checkvars(
        varlist="_page_response_text",
        errorinfo="Lack of login page html. Need to run '_get_login_page' in advance to get it",
    )
    @infomanage(
        successinfo="Successfully resolve IP",
        errorinfo="Failed to resolve IP",
    )
    def _resolve_ip_from_login_page(self):
        self.ip = re.search(
            r'ip\s*:\s*["\'](.*?)["\']', self._page_response_text
        ).group(1)

    @checkvars(
        varlist="ip",
        errorinfo="Lack of local IP. Need to run '_resolve_ip_from_login_page' in advance to get it",
    )
    @infomanage(
        successinfo="Challenge response successfully received",
        errorinfo="Failed to get challenge response, maybe the url_get_challenge_api is not correct."
        "Else check params_get_challenge",
    )
    def _get_challenge(self):
        """
        The 'get_challenge' request aims to ask the server to generate a token
        """
        params_get_challenge = {
            "callback": self.generate_jsonp_string(),  # This value can be any string, but cannot be absent
            "username": self.username,
            "ip": self.ip,
        }
        query_string = urllib.parse.urlencode(params_get_challenge)
        url = f"{self.url_get_challenge_api}?{query_string}"

        req = urllib.request.Request(url, headers=self.header)
        with urllib.request.urlopen(req) as resp:
            self._challenge_response_text = resp.read().decode("utf-8")

    @checkvars(
        varlist="_challenge_response_text",
        errorinfo="Lack of challenge response. Need to run '_get_challenge' in advance",
    )
    @infomanage(
        successinfo="Successfully resolve token",
        errorinfo="Failed to resolve token",
    )
    def _resolve_token_from_challenge_response(self):
        self.token = re.search(
            '"challenge":"(.*?)"', self._challenge_response_text
        ).group(1)

    @checkvars(
        varlist="ip",
        errorinfo="Lack of local IP. Need to run '_resolve_ip_from_login_page' in advance to get it",
    )
    def _generate_info(self):
        info_params = {
            "username": self.username,
            "password": self.password,
            "ip": self.ip,
            "acid": self.ac_id,
            "enc_ver": self.enc,
        }
        info = re.sub("'", '"', str(info_params))
        self.info = re.sub(" ", "", info)

    @checkvars(
        varlist="info",
        errorinfo="Lack of info. Need to run '_generate_info' in advance",
    )
    @checkvars(
        varlist="token",
        errorinfo="Lack of token. Need to run '_resolve_token_from_challenge_response' in advance",
    )
    def _encrypt_info(self):
        self.encrypted_info = "{SRBX1}" + self.get_base64(
            self.get_xencode(self.info, self.token)
        )

    @checkvars(
        varlist="token",
        errorinfo="Lack of token. Need to run '_resolve_token_from_challenge_response' in advance",
    )
    def _generate_md5(self):
        self.md5 = self.get_md5("", self.token)

    @checkvars(
        varlist="md5", errorinfo="Lack of md5. Need to run '_generate_md5' in advance"
    )
    def _encrypt_md5(self):
        self.encrypted_md5 = "{MD5}" + self.md5

    @checkvars(
        varlist="token",
        errorinfo="Lack of token. Need to run '_resolve_token_from_challenge_response' in advance",
    )
    @checkvars(
        varlist="ip",
        errorinfo="Lack of local IP. Need to run '_resolve_ip_from_login_page' in advance to get it",
    )
    @checkvars(
        varlist="encrypted_info",
        errorinfo="Lack of encrypted_info. Need to run '_encrypt_info' in advance",
    )
    def _generate_chksum(self):
        self.chkstr = self.token + self.username
        self.chkstr += self.token + self.md5
        self.chkstr += self.token + self.ac_id
        self.chkstr += self.token + self.ip
        self.chkstr += self.token + self.n
        self.chkstr += self.token + self.vtype
        self.chkstr += self.token + self.encrypted_info

    @checkvars(
        varlist="chkstr",
        errorinfo="Lack of chkstr. Need to run '_generate_chksum' in advance",
    )
    def _encrypt_chksum(self):
        self.encrypted_chkstr = self.get_sha1(self.chkstr)

    def _generate_encrypted_login_info(self):
        self._generate_info()
        self._encrypt_info()
        self._generate_md5()
        self._encrypt_md5()

        self._generate_chksum()
        self._encrypt_chksum()

    @checkvars(
        varlist="ip",
        errorinfo="Lack of local IP. Need to run '_resolve_ip_from_login_page' in advance to get it",
    )
    @checkvars(
        varlist="encrypted_md5",
        errorinfo="Lack of encrypted_md5. Need to run '_encrypt_md5' in advance",
    )
    @checkvars(
        varlist="encrypted_info",
        errorinfo="Lack of encrypted_info. Need to run '_encrypt_info' in advance",
    )
    @checkvars(
        varlist="encrypted_chkstr",
        errorinfo="Lack of encrypted_chkstr. Need to run '_encrypt_chksum' in advance",
    )
    @infomanage(
        successinfo="Login info send successfully",
        errorinfo="Failed to send login info",
    )
    def _send_login_info(self):
        login_info_params = {
            "callback": self.generate_jsonp_string(),  # This value can be any string, but cannot be absent
            "action": "login",
            "username": self.username,
            "password": self.encrypted_md5,
            "ac_id": self.ac_id,
            "ip": self.ip,
            "info": self.encrypted_info,
            "chksum": self.encrypted_chkstr,
            "n": self.n,
            "type": self.vtype,
        }
        query_string = urllib.parse.urlencode(login_info_params)
        url = f"{self.url_login_api}?{query_string}"

        req = urllib.request.Request(url, headers=self.header)
        with urllib.request.urlopen(req) as resp:
            self._login_responce_text = resp.read().decode("utf-8")

    @infomanage(
        successinfo="Logout info send successfully",
        errorinfo="Failed to send logout info",
    )
    def _send_logout_info(self):
        payload = {
            "action": "logout",
            "ac_id": 1,
            "username": self.username,
            "type": 2,
        }
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(self.url_login_api, data=data, headers=self.header)
        with urllib.request.urlopen(req) as resp:
            self.logout_info = "true" if resp.status == 200 else "false"

    @infomanage(
        successinfo="Check info send successfully",
        errorinfo="Failed to send check info",
    )
    def _send_check_info(self):
        try:
            req = urllib.request.Request(self.url_online_api, headers=self.header)
            with urllib.request.urlopen(req) as resp:
                resp_text = resp.read().decode("utf-8")

            if "not_online" in resp_text:
                return False

            items = resp_text.split(",")
            self.online_info = {
                "online": True,
                "username": items[0],
                "login_time": self.time2date(items[1]),
                "now_time": self.time2date(items[2]),
                "used_bytes": self.humanable_bytes(items[6]),
                "used_second": items[7],
                "ip": items[8],
                "balance": items[11],
                "auth_server_version": items[21],
            }
            return True
        except (HTTPError, URLError) as e:
            return False

    @checkvars(
        varlist="_login_responce_text",
        errorinfo="Need _login_responce_text. Run _send_login_info in advance",
    )
    @infomanage(
        successinfo="Login result successfully resolved",
        errorinfo="Cannot resolve login result. Maybe the srun response format is changed",
    )
    def _resolve_login_responce(self):
        logger.info("login result: " + self._login_responce_text)
        match = re.search('"suc_msg":"(.*?)"', self._login_responce_text)

        if match:
            self._login_response_text = match.group(1)
        else:
            self._login_response_text = re.search(
                '"error":"(.*?)"', self._login_responce_text
            ).group(1)

    def _getbyte(self, s, i):
        x = ord(s[i])
        if x > 255:
            raise ValueError("INVALID_CHARACTER_ERR: DOM Exception 5")
        return x

    def get_base64(self, s):
        if not s:
            return ""

        i = 0
        b10 = 0
        x = []
        imax = len(s) - len(s) % 3

        while i < imax:
            b10 = (
                (self._getbyte(s, i) << 16)
                | (self._getbyte(s, i + 1) << 8)
                | self._getbyte(s, i + 2)
            )
            x.append(self._ALPHA[(b10 >> 18) & 63])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._ALPHA[(b10 >> 6) & 63])
            x.append(self._ALPHA[b10 & 63])
            i += 3

        if len(s) - imax == 1:
            b10 = self._getbyte(s, i) << 16
            x.append(self._ALPHA[(b10 >> 18) & 63])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._PADCHAR)
            x.append(self._PADCHAR)
        elif len(s) - imax == 2:
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8)
            x.append(self._ALPHA[(b10 >> 18) & 63])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._ALPHA[(b10 >> 6) & 63])
            x.append(self._PADCHAR)

        return "".join(x)

    def get_md5(self, password, token):
        return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

    def get_sha1(self, value):
        return hashlib.sha1(value.encode()).hexdigest()

    def force(self, msg):
        return bytes(ord(w) for w in msg)

    def ordat(self, msg, idx):
        return ord(msg[idx]) if idx < len(msg) else 0

    def sencode(self, msg, key):
        l = len(msg)
        pwd = []
        for i in range(0, l, 4):
            pwd.append(
                self.ordat(msg, i)
                | (self.ordat(msg, i + 1) << 8)
                | (self.ordat(msg, i + 2) << 16)
                | (self.ordat(msg, i + 3) << 24)
            )
        if key:
            pwd.append(l)
        return pwd

    def lencode(self, msg, key):
        l = len(msg)
        ll = (l - 1) << 2
        if key:
            m = msg[l - 1]
            if m < ll - 3 or m > ll:
                raise ValueError("Invalid length in lencode")
            ll = m
        result = []
        for i in range(l):
            result.append(
                chr(msg[i] & 0xFF)
                + chr((msg[i] >> 8) & 0xFF)
                + chr((msg[i] >> 16) & 0xFF)
                + chr((msg[i] >> 24) & 0xFF)
            )
        return "".join(result)[:ll] if key else "".join(result)

    def get_xencode(self, msg, key):
        if not msg:
            return ""

        pwd = self.sencode(msg, True)
        pwdk = self.sencode(key, False)
        if len(pwdk) < 4:
            pwdk += [0] * (4 - len(pwdk))

        n = len(pwd) - 1
        z = pwd[n]
        y = pwd[0]
        c = 0x86014019 | 0x183639A0
        q = math.floor(6 + 52 / (n + 1))
        d = 0

        while q > 0:
            q -= 1
            d = (d + c) & (0x8CE0D9BF | 0x731F2640)
            e = (d >> 2) & 3
            for p in range(n):
                y = pwd[p + 1]
                m = ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (d ^ y))
                m += pwdk[(p & 3) ^ e] ^ z
                pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
            y = pwd[0]
            m = ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (d ^ y))
            m += pwdk[(n & 3) ^ e] ^ z
            pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD)
            z = pwd[n]

        return self.lencode(pwd, False)

    def generate_jsonp_string(self):
        return f"nyoj{str(int(time.time() * 1000))}"

    def time2date(self, timestamp):
        time_arry = time.localtime(int(timestamp))
        return time.strftime("%Y-%m-%d %H:%M:%S", time_arry)

    def humanable_bytes(self, num_byte):
        num_byte = float(num_byte)
        num_GB, num_MB, num_KB = 0, 0, 0
        if num_byte >= 1024**3:
            num_GB = num_byte // (1024**3)
            num_byte -= num_GB * (1024**3)
        if num_byte >= 1024**2:
            num_MB = num_byte // (1024**2)
            num_byte -= num_MB * (1024**2)
        if num_byte >= 1024:
            num_KB = num_byte // 1024
            num_byte -= num_KB * 1024
        return "{} GB {} MB {} KB {} B".format(num_GB, num_MB, num_KB, num_byte)


class HeartBeat:
    def __init__(self, config_file="setting.ini"):
        self.config = self.load_config(config_file)
        self.srun_ip = self.config["srun_ip"]
        self.username = self.config["username"]
        self.password = self.config["passwd"]
        self.manager = LoginManager(self.srun_ip)

    @staticmethod
    def load_config(config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        return config["DEFAULT"]

    def try_login(self):
        return self.manager.login(self.username, self.password)

    def try_logout(self):
        return self.manager.logout(self.username)

    def check_online(self):
        return self.manager.check_online()

    def online(self):
        try_cnt = 0
        max_try_cnt = 4
        while try_cnt <= max_try_cnt:
            online_info = self.try_login()
            if online_info != None and online_info.get("online"):
                return
            try_cnt += 1
            logger.info(f"Retrying ({try_cnt}/{max_try_cnt}) for user: {self.username}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NYIST ONLINE TOOL",
        epilog="Example: python script.py --option online --config_file setting.ini",
    )
    parser.add_argument(
        "--config_file",
        type=str,
        default="setting.ini",
        help="Path to the configuration file. Default is 'setting.ini'.",
    )
    parser.add_argument(
        "--option",
        type=str,
        choices=["online", "login", "logout", "check"],
        default="online",
        help=(
            "Operation to perform: "
            "'online' to Long-term login&check, "
            "'login' to log in, "
            "'logout' to log out, "
            "'check' to verify online status."
        ),
    )

    args = parser.parse_args()

    heartbeat = HeartBeat(config_file=args.config_file)

    operations = {
        "online": heartbeat.online,
        "login": lambda: print(
            f"Username[{heartbeat.username}] for {heartbeat.srun_ip} Login Info: {heartbeat.try_login()}"
        ),
        "logout": lambda: print(
            f"Username[{heartbeat.username}] for {heartbeat.srun_ip} Logout status: {heartbeat.try_logout()}"
        ),
        "check": lambda: print(
            f"Username[{heartbeat.username}] for {heartbeat.srun_ip} Online status: {heartbeat.check_online()}"
        ),
    }
    operations[args.option]()
