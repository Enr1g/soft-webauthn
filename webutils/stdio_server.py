import contextlib
import json
import os
import pickle
import sys
from ast import literal_eval
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, List
from http import HTTPStatus

import webauthn_software_authenticator as wsa

DEFAULT_DEVICE_FILE = "device.pickle"


def simple_response(status: HTTPStatus, headers: List[str], body: str="", exit_after: bool=True):
    headers.insert(0, f"HTTP/1.1 {status.value} {status.phrase}")
    headers.append(f"Content-Length: {len(body)}")
    print("\r\n".join(headers) + "\r\n\r\n" + body, end="")
    if exit_after:
        sys.exit(0)


def return_not_found():
    simple_response(HTTPStatus.NOT_FOUND, [], "NOT FOUND")


def return_internal_error(msg: str):
    simple_response(HTTPStatus.INTERNAL_SERVER_ERROR, [], f"INTERNAL SERVER ERROR: {msg}")


def convert_array_buffers(d: Dict[str, Any]):
    prefix = "Uint8Array"
    lprefix = len(prefix)

    for k, v in d.items():
        if type(v) == str and v.startswith(prefix):
            d[k] = bytes(literal_eval(v[lprefix:]))
            continue

        if type(v) == dict:
            convert_array_buffers(v)
            continue
        
        if type(v) == list:
            for vv in v:
                convert_array_buffers(vv)
            continue


class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self):
        self.rfile = sys.stdin.buffer
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

# not thread safe
def get_default_device() -> wsa.SoftWebauthnDevice:
    if os.path.exists(DEFAULT_DEVICE_FILE):
        with open(DEFAULT_DEVICE_FILE, "rb") as f:
            device = pickle.load(f)
    else:
        device = wsa.SoftWebauthnDevice(master_key=b'a'*16)
        update_default_device(device)

    return device

# not thread safe
def update_default_device(device: wsa.SoftWebauthnDevice):
    with open(DEFAULT_DEVICE_FILE, "wb") as f:
        pickle.dump(device, f)


def main():
    path_prefix = "/__wsa/webauthn"
    req = HTTPRequestParser()
    device = get_default_device()

    try:
        if not req.path.startswith(path_prefix):
            return_not_found()

        path = req.path[len(path_prefix):]

        if "Content-Length" in req.headers:
            body_len = int(req.headers.get("Content-Length"))
            body = sys.stdin.buffer.read(body_len)

            if req.headers.get("Content-Type", None) == "application/json":
                body = json.loads(body)
                convert_array_buffers(body)

        if path == "/health":
            status_info = (
                "Parsing HTTP Request\n"
                f"Path = {req.path}\n"
                f"Headers = {req.headers.items()}\n"
                f"Default device counter = {device.sign_count}"
            )

            if "Content-Length" in req.headers:
                status_info = f"{status_info}\nBody = {body}"

            simple_response(HTTPStatus.OK, [], status_info)

        if req.command == "POST" and path == "/default/create":
            response = device.create(body, req.headers.get("Origin"))

            response["rawId"] = list(response["rawId"])
            response["response"]["clientDataJSON"] = list(response["response"]["clientDataJSON"])
            response["response"]["attestationObject"] = list(response["response"]["attestationObject"])

            simple_response(HTTPStatus.OK, ["Content-Type: application/json"], json.dumps(response))

        if req.command == "POST" and path == "/default/get":
            response = device.get(body, req.headers.get("Origin"))

            response["rawId"] = list(response["rawId"])
            response["response"]["authenticatorData"] = list(response["response"]["authenticatorData"])
            response["response"]["clientDataJSON"] = list(response["response"]["clientDataJSON"])
            response["response"]["signature"] = list(response["response"]["signature"])

            simple_response(HTTPStatus.OK, ["Content-Type: application/json"], json.dumps(response))

        return_not_found()
    except Exception as e:
        return_internal_error(str(e))
    finally:
        update_default_device(device)


if __name__ == "__main__":
    main()
