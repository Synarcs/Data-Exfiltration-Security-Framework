from concurrent.futures import Future, ThreadPoolExecutor
from functools import cache
import numpy as np 
from typing import Any, Callable, NoReturn, Self
import os, sys, socket, json, subprocess
import logging, signal, threading
import socketserver
import onnxruntime as ort , onnx 
import http.server
import consts, infer 
import datetime 
from argparse import ArgumentParser
from multiprocessing import cpu_count 
from queue import Queue 

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
DEBUG: bool = False 

class OnnxInference(object): 
    model = None 
    model_path = "../dns_sec.onnx"
    def __init__(self) -> None:
        pass 

    def load(self) -> NoReturn: 
        print('[x] Loading the Onnx Inferencing Serialized Model ...')
        if os.path.isfile(self.model_path): 
            self.model = onnx.load(self.model_path) 

        print('The onnx inference Model loaded successfully') 

    def verifyOnnxGraph(self) -> bool:
        return onnx.checker.check_model(self.model, full_check=True) 
    
class HandleInferenceConnHttpLayer7(http.server.BaseHTTPRequestHandler):
    def __init__(self, request: socket.socket, client_address: tuple[str, int], server: socketserver.BaseServer) -> None:
        super().__init__(request, client_address, server)
        global onnxInferenceServer
        
    def infer(self, feature) -> bool:
        return infer.Inference.predict(input_features=np.array(feature, dtype=np.float32).reshape(1, -1)) 

    def do_POST(self) -> None:
        log.debug(f"Received POST request with path: {self.path}")
        if self.path == "/onnx/dns" or self.path == "/onnx/dns/ing": 
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()

                request_body = json.loads(post_data)
                if DEBUG:
                    log.debug(f'Received request for inference {request_body}')
                # True if benign else False 
                # TODO: Run onnx evaluation for the model to process the data against trained deep learning model 

                if self.path == "/onnx/dns":
                    evalPrediction = []

                    for feature in request_body['Features']:
                        evalPrediction.append(self.infer(feature))

                    response = {
                        "threat_type": True if any(evalPrediction) else False, # for now to drop all the pakcet hitting the remote inference server 
                        "protocol": "DNS" 
                    }
                    self.send_response(http.HTTPStatus.OK) 
                    self.send_header("Content-Type", "application/json") 
                    response_body = json.dumps(response).encode('utf-8')
                    if DEBUG:
                        log.debug(f"Sending response: {response_body}")
                    self.wfile.write(response_body)
                    return 
                elif self.path == "/onnx/dns/ing":
                    evalPrediction = []
                    for feature in request_body['Features']:
                        evalPrediction.append(self.infer(feature))
                    
                    response = {
                        "threat_type": evalPrediction, 
                        "protocol": "DNS"
                    }
                    self.send_response(http.HTTPStatus.OK) 
                    self.send_header("Content-Type", "application/json") 
                    response_body = json.dumps(response).encode('utf-8')
                    if DEBUG:
                        log.debug(f"Sending response: {response_body}")
                    self.wfile.write(response_body) 
                    
            except Exception as e:
                log.error(f"Error in do_POST: {str(e)}")
        else:
            payload = {
                "err": "Inference Server Dont Support other inference modes"
            }
            self.send_response(http.HTTPStatus.NOT_IMPLEMENTED) 
            self.send_header("Content-Type", "application/json") 
            self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self) -> None:
        log.debug(f"Received GET request with path: {self.path}")
        if self.path == "/health":
            try:
                sample = {
                    "time": datetime.datetime.now().isoformat(),
                    "version": "0.0.1", 
                    "status": "Inference Server is UP and healthy" 
                }
                self.send_response(http.HTTPStatus.OK)
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

def run_egress_server(controllerMode: bool = False, threadQueue: Queue = None) -> None:
    if threadQueue is None:
        threadQueue = Queue()
    
    print('[x] Running the Egress Unix socket server on thread', threading.current_thread().name)
    inferSock: str = consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS if not controllerMode else consts.ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_EGRESS

    if os.path.exists(inferSock):
        os.unlink(inferSock)

    try:
        httpd = ThreadingUnixSocketHttpServer(inferSock, HandleInferenceConnHttpLayer7)
        print(f'HTTP Server over unix socket transport on {inferSock}')
        
        tt = threading.Thread(target=httpd.serve_forever())
        tt.start()
        while True:
            ss = threadQueue.get() 
            log.info("closing the ingress server")
            if ss:
                return 

    except Exception as err:
        print(f"Runtime exception occurred while starting the inference server over unix sock: {err}")

    finally:
        if os.path.exists(inferSock):
            os.unlink(inferSock)


def run_ingress_server(controllerMode: bool = False, threadQueue: Queue = None) -> None:
    if threadQueue is None:
        threadQueue = Queue()

    print('[x] Running the Ingress Unix socket server on thread', threading.current_thread().name)
    inferSock: str = consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS if not controllerMode else consts.ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_INGRESS

    if os.path.exists(inferSock):
        os.unlink(inferSock)

    try:
        httpd = ThreadingUnixSocketHttpServer(inferSock, HandleInferenceConnHttpLayer7)
        print(f'HTTP Server over unix socket transport on {inferSock}')
        
        tt = threading.Thread(target=httpd.serve_forever())
        tt.start()
        while True:
            ss = threadQueue.get() 
            log.info("closing the ingress server")
            if ss:
                return 

    except Exception as err:
        print(f"Runtime exception occurred while starting the inference server over unix sock: {err}")

    finally:
        if os.path.exists(inferSock):
            os.unlink(inferSock)


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser() 
    parser.add_argument('-c', '--controller', type=bool, required=False, default=False, help="Run the ONNX inference unix server for inference over controller server")
    args = parser.parse_args()

    ingressQueue: Queue = Queue()
    egressQueue: Queue = Queue() 

    onnxInferenceServer: OnnxInference = OnnxInference()
    onnxInferenceServer.load()

    executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=cpu_count())

    def killSock(sig, frame) -> None:
        print(f"Received {sig}, shutting down inference servers...")

        try:
            if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS):
                os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
            if os.path.exists(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS): 
                os.unlink(consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)
            
            ingressQueue.put(True)
            egressQueue.put(True)

        except OSError as err: 
            print(f"OS Error: {err}")
        except Exception as err:
            print(f"Runtime Error during shutdown: {err}")
        finally:
            executor.shutdown(wait=False)
            print("Servers shut down gracefully.")
            os._exit(0)  

    signal.signal(signal.SIGINT, killSock)
    signal.signal(signal.SIGTERM, killSock)

    print(f'Starting the inference server over Unix socket transport (PID: {os.getpid()})')

    try:
        ingress: Future = executor.submit(run_ingress_server, args.controller, ingressQueue) 
        egress: Future = executor.submit(run_egress_server, args.controller, egressQueue)  
    except KeyboardInterrupt:
        killSock(signal.SIGINT, None)