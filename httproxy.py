#!/usr/bin/env python
import os
import sys
import argparse
import tempfile
import random
import datetime
import threading
import logging
import urllib3
from ssl import SSLError
from collections import OrderedDict

import requests
from OpenSSL import crypto

from flask import Flask
from flask import Response
from flask import request
from flask_basicauth import BasicAuth
from gevent.pywsgi import WSGIServer
import gevent


global ARGS
global CERT
global GUI

UPSTREAM_MAP = {}

APP = Flask(__name__)
LOCK = threading.Lock()
WHITE_LIST = OrderedDict()

WHITE_LIST_SIZE = 5
WHITE_TIME_DELTA = datetime.timedelta(hours=1)

ENV_HTTPROXY_AUTH_USERNAME = "HTTPROXY_AUTH_USERNAME"
ENV_HTTPROXY_AUTH_PASSWORD = "HTTPROXY_AUTH_PASSWORD"
DEFAULT_HTTPROXY_AUTH_USERNAME = "httproxy"
DEFAULT_HTTPROXY_AUTH_PASSWORD = "password"


class WhiteListBasicAuth(BasicAuth):

    def authenticate(self):

        remote_addr = request.remote_addr
        if ARGS.using_x_real_ip:
            remote_addr = request.headers.get("X-Real-Ip", remote_addr)

        if remote_addr in WHITE_LIST:
            if (datetime.datetime.now() - WHITE_LIST[remote_addr]) < WHITE_TIME_DELTA:
                WHITE_LIST[remote_addr] = datetime.datetime.now()
                return True
            else:
                with LOCK:
                    del WHITE_LIST[remote_addr]

        authenticated = super().authenticate()
        if authenticated:
            with LOCK:
                if len(WHITE_LIST) >= WHITE_LIST_SIZE:
                    WHITE_LIST.popitem(last=False)
                WHITE_LIST[remote_addr] = datetime.datetime.now()

        return authenticated


class QuietWSGIServer(WSGIServer):
    def wrap_socket_and_handle(self, *args, **kwargs):
        try:
            super().wrap_socket_and_handle(*args, **kwargs)
        except SSLError as e:
            logging.error("[TLS] SSL handshake failed ignored: %s", e)


def set_cors_headers(response_headers, request_headers):
    response_headers["Access-Control-Allow-Origin"] = GUI
    response_headers["Access-Control-Allow-Credentials"] = 'true'
    for header in ["Access-Control-Allow-Headers", "Access-Control-Allow-Methods"]:
        response_headers[header] = "*"
    if "Access-Control-Request-Headers" in request_headers:
        response_headers["Access-Control-Allow-Headers"] = request_headers["Access-Control-Request-Headers"]
    if "Access-Control-Request-Method" in request_headers:
        response_headers["Access-Control-Allow-Methods"] = request_headers["Access-Control-Request-Method"]


def handle_request():

    port = int(request.environ.get('SERVER_PORT'))
    path = request.path

    url = get_uri(port, path)

    resp = requests.request(request.method, url,
                            headers=request.headers,
                            data=request.data,
                            timeout=30,
                            stream=True,
                            verify=False)

    def generate_stream():
        for chunk in resp.iter_content(4096):
            yield chunk

    upstream_headers = dict(resp.headers)
    response_headers = {}
    for header in upstream_headers:
        if header.lower() in ['content-length', 'connection', 'content-encoding', 'transfer-encoding']:
            continue
        response_headers[header] = upstream_headers[header]

    set_cors_headers(response_headers, request.headers)

    return Response(generate_stream(), status=resp.status_code, headers=response_headers)


@APP.route('/', defaults={'path': ''})
@APP.route('/<path:path>', methods=['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'])
def catch_all(path):
    return handle_request()


def get_uri(port, path):
    return UPSTREAM_MAP[port] + path


def generate_cert(cert_path):
    """
    Use OpenSSL to create a new Cert and Key
    """
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "PY"
    cert.get_subject().ST = "Python HTTProxy"
    cert.get_subject().OU = "Python HTTProxy"
    cert.get_subject().CN = "Python HTTProxy"
    # Use a unique serial number
    cert.set_serial_number(random.randint(1, 2147483647))
    cert.gmtime_adj_notBefore(0)
    # Expire cert after 1 year
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha256")

    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode()

    # Write to file if needed
    if cert_path is not None:
        with open(cert_path, "w") as f:
            f.write(key_pem)
            f.write(cert_pem)

    # Return cert and key if required
    return cert_pem, key_pem


def check_args():

    if len(ARGS.upstream) != len(ARGS.port):
        sys.exit("Num of upstream must be equal to port")

    for i, port in enumerate(ARGS.port):
        UPSTREAM_MAP[port] = ARGS.upstream[i]


def auth_app():

    auth = WhiteListBasicAuth(APP)

    APP.config["BASIC_AUTH_USERNAME"] = os.environ.get(ENV_HTTPROXY_AUTH_USERNAME, DEFAULT_HTTPROXY_AUTH_USERNAME)
    APP.config["BASIC_AUTH_PASSWORD"] = os.environ.get(ENV_HTTPROXY_AUTH_PASSWORD, DEFAULT_HTTPROXY_AUTH_PASSWORD)

    for endpoint, view_func in APP.view_functions.items():
        if endpoint != 'static':
            APP.view_functions[endpoint] = auth.required(view_func)


def run_app():

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    auth_app()

    for port in ARGS.port:
        https_server = QuietWSGIServer((ARGS.bind, port), APP, certfile=CERT)
        https_server.start()

    while True:
        gevent.sleep(60)


def parse_args():
    global ARGS
    global GUI

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bind",
        "-b",
        default="127.0.0.1",
        metavar="ADDRESS",
        help="Specify alternate bind address " "[default: all interfaces]",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        action="append",
        required=True,
        help="Specify alternate port [default: 5000]",
    )
    parser.add_argument(
        "--existing-cert",
        "-e",
        dest="existing_cert",
        help="Specify an existing cert to use "
        "instead of auto-generating one. File must contain "
        "both DER-encoded cert and private key",
    )
    parser.add_argument(
        "--save-cert",
        "-s",
        dest="save_cert",
        action="store_true",
        help="Save certificate file in current directory",
    )
    parser.add_argument(
        "--up-stream",
        "-u",
        dest="upstream",
        action="append",
        required=True,
        help="Upstream to be proxied",
    )
    parser.add_argument(
        "--host",
        "-o",
        help="Host to be accessed",
    )
    parser.add_argument(
        "-x",
        dest="using_x_real_ip",
        action="store_true",
        default=False,
        help="Using X-Real-Ip in header as real client IP. "
        "Caution: This feature must ONLY be enabled when a reverse proxy is in place and setting the required header.",
    )
    ARGS = parser.parse_args()
    GUI = "https://{}:{}".format(ARGS.host or ARGS.bind, ARGS.port[0])
    check_args()


def main():

    global ARGS
    global CERT

    parse_args()

    # If supplied cert use that
    if ARGS.existing_cert is not None:
        CERT = ARGS.existing_cert
        run_app()
    # Else generate a cert and key pair and use that
    elif ARGS.save_cert:
        CERT = os.path.join(os.getcwd(), "cert.pem")
        generate_cert(CERT)
        run_app()
    else:
        with tempfile.TemporaryDirectory(prefix="pythonHTTProxy_") as tmp_dir:
            CERT = os.path.join(tmp_dir, "cert.pem")
            generate_cert(CERT)
            run_app()


if __name__ == '__main__':
    main()
