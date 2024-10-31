from concurrent.futures import Future, ThreadPoolExecutor
import datetime
from io import StringIO
from typing import Any, Callable, NoReturn, Self
import os, sys, socket, json 
import logging, signal, threading
import socketserver
import onnxruntime as ort , onnx 
import http.server 
import consts 
from abc import ABC, abstractmethod 


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
DEBUG: bool = False 

def killSock(sig, frame) -> None:
    print(f"Received a {sig}, removing the unix socket")
    try:
        if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS):
            os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
            os.remove(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
        if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS): 
            os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)
            os.remove(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)
    except OSError as err: pass 
    except Exception as err:
        print(f"Error removing the unix socket Runtime Error: {err}")
    finally:
        sys.exit(0)

class OnnxInference(object): 
    model = None 
    model_path = "../dns_sec.onnx"
    def __init__(self) -> None:
        pass 

    def load(self) -> NoReturn: 
        print('[x] Loading the Onnx Inferencing Mode ...')
        if os.path.isfile(self.model_path): 
            self.model = onnx.load(self.model_path) 

        print('The onnx inference Model loaded successfully') 

    def verifyOnnxGraph(self) -> bool:
        return onnx.checker.check_model(self.model, full_check=True) 
    
onnxInferenceServer: OnnxInference = OnnxInference() 
onnxInferenceServer.load()

class HandleInferenceConnHttpLayer7(http.server.BaseHTTPRequestHandler):
    def __init__(self, request: socket.socket, client_address: tuple[str, int], server: socketserver.BaseServer) -> None:
        super().__init__(request, client_address, server)
        global onnxInferenceServer
        
    def infer(self) -> bool:
        return True 

    def do_POST(self) -> None:
        log.debug(f"Received POST request with path: {self.path}")
        if self.path == "/onnx/dns":
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

                evalFeatureCount = len(request_body['Features']) 
                with ThreadPoolExecutor(max_workers=evalFeatureCount) as executor:
                    executor.map(self.infer, request_body["Features"])

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
        if DEBUG:
            print(f"Request received from {client_address}") 
        return (request, ["local", 0])

class ThreadingUnixSocketHttpServer(socketserver.ThreadingMixIn, UnixSocketHttpServer):
    allow_reuse_address = True
    daemon_threads = True 
    request_queue_size = 1 << 10

    def __init__(self, server_address: str | Any, RequestHandlerClass: Callable[[Any, Any, Self], Any], bind_and_activate: bool = True) -> None:
        super(ThreadingUnixSocketHttpServer, self).__init__(server_address, RequestHandlerClass, bind_and_activate)

        self.thread_pool = []
        self.max_threads = self.request_queue_size

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def server_bind(self) -> None:
        try:
            os.unlink(self.server_address)
        except Exception as err: 
            pass 

        return super().server_bind()


def run_egress_server() -> None:
    print('[x] Running the Egress Unix socket server on thread ', threading.current_thread().name)
    if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS):
        os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)

    try:
        httpd = ThreadingUnixSocketHttpServer(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS, HandleInferenceConnHttpLayer7)
        print(f'HTTP Server over unix socket transport on {consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS}')
        httpd.serve_forever()
    except Exception as err:
        print(f"Runtime exception occurred while starting the inference server over unix sock: {err}")
    finally:
        if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS):
            os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)

def run_ingress_server() -> None:
    print('[x] Running the Ingress Unix socket server on thread ', threading.current_thread().name)
    if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS):
        os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)

    try:
        httpd = ThreadingUnixSocketHttpServer(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS, HandleInferenceConnHttpLayer7)
        print(f'HTTP Server over unix socket transport on {consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS}')
        httpd.serve_forever()
    except Exception as err:
        print(f"Runtime exception occurred while starting the inference server over unix sock: {err}")
    finally:
        if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS):
            os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, killSock)
    signal.signal(signal.SIGTERM, killSock)
    print('Starting the inference server over unix socket transport with process ', os.getpid())
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            ingress: Future = executor.submit(run_ingress_server)
            egress: Future = executor.submit(run_egress_server)
    except KeyboardInterrupt:
        print("Server stopped by user")
    finally:
        killSock(None, None)