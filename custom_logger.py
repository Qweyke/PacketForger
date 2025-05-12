import logging
from typing import cast

from colorama import init, Fore, Style

init(autoreset=True)

PACKET_LEVEL = 15
logging.addLevelName(PACKET_LEVEL, "PACKET")


class DpiLogger(logging.Logger):
    def __init__(self, name: str, level=logging.NOTSET):
        super().__init__(name=name, level=level)

    def packet(self, msg, sub_lvl=None, *args, **kwargs):
        # extra = kwargs.get("extra", {})
        # extra["sub_lvl"] = sub_lvl if sub_lvl else "-"
        # kwargs["extra"] = extra

        if self.isEnabledFor(PACKET_LEVEL):
            self._log(PACKET_LEVEL, msg, args, **kwargs)

    def info(self, msg, sub_lvl=None, *args, **kwargs):
        # extra = kwargs.get("extra", {})
        # extra["sub_lvl"] = sub_lvl if sub_lvl else "-"
        # kwargs["extra"] = extra

        if self.isEnabledFor(logging.INFO):
            self._log(logging.INFO, msg, args, **kwargs)


class ColorFormatter(logging.Formatter):
    def format(self, record):
        level = record.levelno
        if not hasattr(record, "sub_lvl"):
            record.sub_lvl = "-"

        if level == logging.DEBUG:
            record.msg = f"{Fore.YELLOW}{record.msg}{Style.RESET_ALL}"
        elif level == logging.INFO:
            record.msg = f"{Fore.LIGHTMAGENTA_EX}{record.msg}{Style.RESET_ALL}"
        elif level == logging.WARNING:
            record.msg = f"{Fore.LIGHTYELLOW_EX}{record.msg}{Style.RESET_ALL}"
        elif level == logging.ERROR:
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        elif level == PACKET_LEVEL:
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


def get_dpi_logger(name: str = "dpi") -> DpiLogger:
    logger = logging.getLogger(name)
    return cast(DpiLogger, logger)


logging.setLoggerClass(DpiLogger)
dpi_logger = get_dpi_logger()
dpi_logger.setLevel(logging.DEBUG)

dpi_handler = logging.StreamHandler()
dpi_handler.setFormatter(ColorFormatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
dpi_logger.addHandler(dpi_handler)
