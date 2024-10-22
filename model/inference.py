import datetime
import multiprocessing
from typing import NoReturn
import os, sys, socket, json 
import logging, signal
import socketserver
import http.server 

ONNX_INFERENCE_UNIX_SOCKET = "/run/onnx-inference.sock"

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def killSock(sig, frame) -> None:
    print(f"Received a {sig}, removing the unix socket")
    try:
        os.remove(ONNX_INFERENCE_UNIX_SOCKET)
    except OSError as err:
        print(f"Error removing the unix socket: {err}")
    finally:
        sys.exit(0)

class HandleInferenceConnHttpLayer7(http.server.BaseHTTPRequestHandler):

    def do_POST(self) -> None:
        log.debug(f"Received POST request with path: {self.path}")
        if self.path == "/onnx":
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()

                request_body = json.loads(post_data)
                print('Received request for inference ', request_body)
                # True if benign else False 
                # TODO: Run onnx evaluation for the model to process the data against trained deep learning model 
                response = {
                    "threat_type": False
                }
                response_body = json.dumps(response).encode('utf-8')
                log.debug(f"Sending response: {response_body}")
                self.wfile.write(response_body)
                return
            except Exception as e:
                log.error(f"Error in do_POST: {str(e)}")

    def do_GET(self) -> None:
        log.debug(f"Received GET request with path: {self.path}")
        if self.path == "/onnx":
            try:
                sample = {
                    "time": datetime.datetime.now().isoformat(),
                }
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                response_body = json.dumps(sample).encode('utf-8')
                log.debug(f"Sending response: {response_body}")
                self.wfile.write(response_body)
                return 
            except Exception as e:
                log.error(f"Error in do_GET: {str(e)}")
                self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, f"Internal server error: {str(e)}")
                return 
        else:
            self.send_error(http.HTTPStatus.BAD_REQUEST, "The inference server cannot process the request")

class UnixSocketHttpServer(socketserver.UnixStreamServer):
    def get_request(self):
        request, client_address = super(UnixSocketHttpServer, self).get_request()
        print(f"Request received from {client_address}") 
        return (request, ["local", 0])

def run_server() -> None:
    if os.path.exists(ONNX_INFERENCE_UNIX_SOCKET):
        os.unlink(ONNX_INFERENCE_UNIX_SOCKET)

    try:
        httpd = UnixSocketHttpServer((ONNX_INFERENCE_UNIX_SOCKET), HandleInferenceConnHttpLayer7)
        print(f'HTTP Server over unix socket transport on {ONNX_INFERENCE_UNIX_SOCKET}')
        httpd.serve_forever()
    except Exception as err:
        print(f"Runtime exception occurred while starting the inference server over unix sock: {err}")
    finally:
        if os.path.exists(ONNX_INFERENCE_UNIX_SOCKET):
            os.unlink(ONNX_INFERENCE_UNIX_SOCKET)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, killSock)
    signal.signal(signal.SIGTERM, killSock)
    print('Starting the inference server over unix socket transport with process ', os.getpid())
    try:
        run_server()
    except KeyboardInterrupt:
        print("Server stopped by user")
    finally:
        killSock(None, None)