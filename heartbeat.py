from LoginManager import LoginManager

import configparser
import argparse
import logging

logging.basicConfig(
    format="%(asctime)s.%(msecs)03d [%(filename)s:%(lineno)d] %(message)s",
    datefmt="## %Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


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
            "'online' to Long-term login check, "
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
