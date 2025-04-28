import argparse
import base64
import json
import logging
import socket
import ssl
import sys
import urllib.parse
from typing import List, TypedDict, NotRequired, Union, Tuple, Optional
from urllib.parse import ParseResult

import certifi
import dns.resolver
import httptools


class HTTPResponseParser:
    def __init__(self):
        self.headers = {}
        self.body = bytearray()
        self.status_code = None
        self.reason = None
        self.http_version = None
        self.parser = httptools.HttpResponseParser(self)

    def on_status(self, status):
        self.reason = status.decode("utf-8", errors="replace")

    def on_header(self, name, value):
        self.headers[name.decode("utf-8")] = value.decode("utf-8")

    def on_body(self, body):
        self.body.extend(body)

    def feed_data(self, data):
        self.parser.feed_data(data)


def parse_http_response(response_bytes):
    parser = HTTPResponseParser()
    parser.feed_data(response_bytes)
    return {
        "status_code": parser.parser.get_status_code(),
        "reason": parser.reason,
        "headers": parser.headers,
        "body": bytes(parser.body),
    }


def svcbname(parsed: ParseResult):
    """Derive DNS name of SVCB/HTTPS record corresponding to target URL"""
    if parsed.scheme == "https":
        if (parsed.port or 443) == 443:
            return parsed.hostname
        else:
            return f"_{parsed.port}._https.{parsed.hostname}"
    elif parsed.scheme == "http":
        if (parsed.port or 80) in (443, 80):
            return parsed.hostname
        else:
            return f"_{parsed.port}._https.{parsed.hostname}"
    else:
        # For now, no other scheme is supported
        return None


def get_ech_configs(domain, follow_alias: bool = True) -> Tuple[Optional[str], List[bytes]]:
    try:
        answers = dns.resolver.resolve(domain, "HTTPS")
    except dns.resolver.NoAnswer:
        logging.warning(f"No HTTPS record found for {domain}")
        return None, []
    except Exception as e:
        logging.critical(f"DNS query failed: {e}")
        sys.exit(1)

    answers = list(filter(lambda a: a.rdtype == 65, answers))

    if len(answers) == 0:
        logging.warning(f"No echconfig found in HTTPS record for {domain}")
        return None, []

    answers.sort(key=lambda a: a.priority)
    if answers[0].priority == 0:
        logging.debug(f"HTTPS record using AliasMode (0). Looking instead at {answers[0].target}")
        return get_ech_configs(answers[0].target.to_text(True), False)

    configs = []

    for rdata in answers:
        if hasattr(rdata, "params"):
            params = rdata.params
            echconfig = params.get(5)
            if echconfig:
                configs.append(echconfig.ech)

    return None if follow_alias else domain, configs

def access_origin(hostname, port, path='', ech_configs=None, enable_retry=True, target=None) -> bytes:
    logging.debug(f"Accessing service providing https://{hostname}:{port}/")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certifi.where())
    context.options |= ssl.OP_ECH_GREASE
    for config in ech_configs:
        try:
            context.set_ech_config(config)
            context.check_hostname = False
        except ssl.SSLError as e:
            logging.error(f"SSL error for {hostname}:{port} -- {e}")
            pass
    logging.debug(f"Target is {target} and hostname is {hostname}:{port}")
    with socket.create_connection((target or hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False) as ssock:
            try:
                ssock.do_handshake()
                status = ssock.get_ech_status()
                logging.debug("Handshake completed with ECH status: %s", ssock.get_ech_status().name)
                logging.debug("Inner SNI: %s, Outer SNI: %s", ssock.server_hostname, ssock.outer_server_hostname)
            except ssl.SSLError as e:
                if enable_retry:
                    retry_config = ssock._sslobj.get_ech_retry_config()
                    if retry_config:
                        logging.debug("Received a retry config: %s", base64.b64encode(retry_config))
                        # return get_http(hostname, port, path, [retry_config])
                        return access_origin(hostname, port, path, [retry_config], False, target)
                logging.error(f"SSL error for {hostname}:{port} -- {e}")

            response = b''
            if path != None:
                logging.debug(f"Performing GET request for https://{hostname}:{port}/{path}")
                request = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
                ssock.sendall(request.encode('utf-8'))
                while True:
                    data = ssock.recv(4096)
                    if not data:
                        break
                    response += data
            return response


def get_http(hostname, port, path, ech_configs, target) -> bytes:
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, target=target)


def get(url: str, force_grease: bool):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname
    if force_grease:
        target, ech_configs = None, []
    else:
        target, ech_configs = get_ech_configs(svcbname(parsed))
    logging.debug("Discovered ECHConfig values: %s", [base64.b64encode(config) for config in ech_configs])
    request_path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
    raw = get_http(domain, parsed.port or 443, request_path, ech_configs, target)
    return parse_http_response(raw)


def cmd_get(url: str, force_grease: bool) -> None:
    """Retrieves data from a given URL."""
    print(get(url, force_grease))


def cmd_echconfig(url: str) -> None:
    """Print the bas64-encoded ECHConfig values for a given URL."""
    parsed = urllib.parse.urlparse(url)
    for config in get_ech_configs(svcbname(parsed)):
        print(base64.b64encode(config).decode("utf-8"))


class GetTarget(TypedDict):
    description: NotRequired[str]
    expected: NotRequired[str]
    url: str


def read_targets_list() -> List[GetTarget]:
    try:
        input_json = sys.stdin.read()
        input_data = json.loads(input_json)

        if not isinstance(input_data, list):
            logging.critical("Invalid input format: JSON input must be a list")
            sys.exit(1)

        for item in input_data:
            if isinstance(item, dict):
                if "url" not in item:
                    logging.error(f"Invalid input format, missing url: {item}")
                    sys.exit(1)
                continue
            if not isinstance(item, str):
                logging.critical(
                    f"Invalid format: Each entry must be a string or object, but got {item}"
                )
                sys.exit(1)
        return input_data
    except json.JSONDecodeError as e:
        logging.critical(f"Error decoding JSON input: {e}")
        sys.exit(1)


def cmd_getlist(demo: bool, force_grease: bool) -> None:
    targets: List[Union[GetTarget, str]]
    if demo:
        targets = json.load(open("targets.json"))
    else:
        targets = read_targets_list()
    for target in targets:
        logging.debug("--------------------------------------------------------")
        if isinstance(target, str):
            cmd_get(target, force_grease)
            continue
        logging.debug("Target description: %s", target["description"])
        logging.debug("Expected ECH status: %s", target["expected"])
        cmd_get(target["url"], force_grease)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A Python HTTPS client with TLS ECH support.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(
        title="subcommands", dest="command", help="Available subcommands"
    )

    echconfig_parser = subparsers.add_parser(
        "echconfig", help="Print ECHConfig values from DNS (base64 encoded)."
    )
    echconfig_parser.add_argument("url", help="URL to fetch config for.")
    echconfig_parser.set_defaults(func=cmd_echconfig)

    get_parser = subparsers.add_parser("get", help="Fetch a URL.")
    get_parser.add_argument("url", help="URL to fetch")
    get_parser.add_argument(
        "-g", "--force-grease", action="store_true", help="Force GREASE"
    )
    get_parser.set_defaults(func=cmd_get)

    getlist_parser = subparsers.add_parser(
        "getlist", help="Iterate through a list of targets."
    )
    getlist_parser.add_argument(
        "-g", "--force-grease", action="store_true", help="Force GREASE"
    )
    getlist_parser.add_argument("--demo", help="Use a set of demo targets.", action="store_true")
    getlist_parser.set_defaults(func=cmd_getlist)

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logging.debug(f"Command line arguments: {args}")

    if args.command is None:
        parser.print_help()
        return

    if args.command == "getlist":
        args.func(args.demo, args.force_grease)
        return

    try:
        args.func(args.url, args.force_grease)
    except AttributeError as e:
        logging.critical(
            f"Error: Subcommand '{args.command}' was called, but it requires additional arguments: {e}"
        )


if __name__ == "__main__":
    main()
