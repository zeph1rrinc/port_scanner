from loguru import logger

from . import scan


def main():
    logger.debug(scan(domain="localhost", result_path="zeph1rr.ru.json"))


if __name__ == "__main__":
    main()
