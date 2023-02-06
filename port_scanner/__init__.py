import nmap
import json

from loguru import logger
from typing import Union


def scan(domain: str, port_range: str = "0-65535", result_path: str = None) -> Union[dict, bool]:
    """
    scanning domain for open ports

    :param domain: hostname to scan. For example "example.com"
    :type domain: str

    :param port_range: range of ports to scan. For example "22-443"
    :type port_range: str

    :param result_path: [OPTIONAl] path to file for json dump result. For example "/home/user/result.json
    :type result_path: str

    :return: dict with data about opened ports or bool value if result_path is set
    """
    scanner = nmap.PortScanner()
    result = []
    scanner.scan(domain, port_range)

    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol].keys()
            for port in ports:
                result.append({
                    "protocol": protocol,
                    "port": port,
                    **scanner[host][protocol][port]
                })
    data = {"domain": domain, "ports": result}
    if result_path is None:
        return data
    try:
        with open(result_path, "w") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)
        return True
    except Exception as _ex:
        logger.error(_ex)
        return False
