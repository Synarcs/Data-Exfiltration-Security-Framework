from concurrent.futures import Future, ThreadPoolExecutor
from functools import cache
import numpy as np 
from typing import Any, Callable, NoReturn, Self
import os, sys, socket, json, subprocess
import logging, signal, threading
import socketserver
import onnxruntime as ort , onnx 
import http.server
import consts 
import datetime 
from argparse import ArgumentParser
from pathlib import Path 
from multiprocessing import cpu_count 
from queue import Queue 

log = logging.getLogger(__name__)
DEBUG: bool = False 
log.setLevel(logging.INFO if not DEBUG else logging.DEBUG)


parser = ArgumentParser() 
parser.add_argument('-c', '--controller', type=bool, required=False, default=False, help="Run the ONNX inference unix server for inference over controller server")
parser.add_argument('-m', '--model_path', type=str, required=True, help="Path to the ONNX model")
args = parser.parse_args()
model: Path = Path('../model/dns_sec.onnx' if not os.path.exists(args.model_path) else args.model_path).absolute()
isControllerEnabled: bool = True if args.controller == True else False
session = ort.InferenceSession(model) 

if not os.path.exists(model):
    print('the required trained onnx model not found')
    os.exit(signal.SIGKILL) 

input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name


class HandleInferenceConnHttpLayer7(http.server.BaseHTTPRequestHandler):
    def __init__(self, request: socket.socket, client_address: tuple[str, int], server: socketserver.BaseServer) -> None:
        super().__init__(request, client_address, server)
        
    def infer(self, input_features) -> bool:
        feature_vec = np.array(input_features, dtype=np.float32).reshape(1, -1)
        if feature_vec.shape != (1, 8):
            log.error('cannot infer a broken vector tensor for model inference')
            return 
        return True if session.run([output_name], {input_name: feature_vec})[0][0][0] > 0.5 else False 

    def do_POST(self) -> None:
        log.debug(f"Received POST request with path: {self.path}")
        if self.path == "/onnx/dns" or self.path == "/onnx/dns/ing": 
            try:
                if DEBUG:
                    log.info(f'Current thread handle the request {threading.current_thread().getName()}')
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
                    if not DEBUG:
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
            self.send_error(http.HTTPStatus.BAD_REQUEST, "The ference server cannot process the request")

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
    
    log.info('[x] Running the Egress Unix socket server on thread {threading.current_thread().name}')
    if controllerMode:
        log.info(f'[x] Running Egress server in controller mode')
    
    inferSock: str = consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS if not controllerMode else consts.ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_EGRESS

    if os.path.exists(inferSock):
        os.unlink(inferSock)

    # os.chmod(inferSock, 777) # only for testing TODO: Enforce strict MAC and kernel LSM for strict permission over the  unix sock fd 
    try:
        httpd = ThreadingUnixSocketHttpServer(inferSock, HandleInferenceConnHttpLayer7)
        print(f'Current thread handling{threading.current_thread().name} HTTP Server over unix socket transport for egress inference {inferSock}')
        
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

    log.info(f'[x] Running the Ingress Unix socket server on thread {threading.current_thread().name}')
    if controllerMode:
        log.info(f'[x] Running Ingress server in controller mode')
    
    inferSock: str = consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS if not controllerMode else consts.ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_INGRESS

    if os.path.exists(inferSock):
        os.unlink(inferSock)

    # os.chmod(inferSock, 777) # only for testing TODO: Enforce strict MAC and kernel LSM for strict permission over the  unix sock fd 
    try:
        httpd = ThreadingUnixSocketHttpServer(inferSock, HandleInferenceConnHttpLayer7)
        print(f'Current thread handling{threading.current_thread().name} HTTP Server over unix socket transport for ingress inference {inferSock}')
        
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


def initSockKernelFsMnt(isController: bool = False): 
    if isController:
        return 
    
    # ensure there no dangling kernfs mounted unix sock with no live process serving the socket
    if os.path.exists(consts.ONNX_MNT_PATH):
        if len(os.listdir(consts.ONNX_MNT_PATH)) > 0: # un gracefully other running mount socket
            for fd in os.listdir(consts.ONNX_MNT_PATH):
                if fd == consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS or fd == consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS:
                    os.unlink(fd)
                    os.remove(fd)
        os.removedirs(consts.ONNX_MNT_PATH)
    
    os.mkdir(consts.ONNX_MNT_PATH)

def cleanSockKernelFsMnt(egressFd: str, ingressFd: str, isController: bool):
    if os.path.exists(egressFd):
        os.unlink(egressFd)
    if os.path.exists(ingressFd): 
        os.unlink(ingressFd) 
    if not isController:
        os.removedirs(consts.ONNX_MNT_PATH)
 
if __name__ == "__main__":
    from argparse import ArgumentParser


    ingressQueue: Queue = Queue()
    egressQueue: Queue = Queue() 


    executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=cpu_count())

    def killSock(sig, frame) -> None:
        print(f"Received {sig}, shutting down inference servers...")

        try:
            ingressFd = consts.ONNX_INFERENCE_UNIX_SOCKET_INGRESS if not isControllerEnabled else consts.ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_INGRESS
            egressFd = consts.ONNX_INFERENCE_UNIX_SOCKET_EGRESS if not isControllerEnabled else consts.ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_EGRESS
  
            cleanSockKernelFsMnt(egressFd, ingressFd, isControllerEnabled)
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
    initSockKernelFsMnt(isControllerEnabled)

    try:
        ingress: Future = executor.submit(run_ingress_server, args.controller, ingressQueue) 
        egress: Future = executor.submit(run_egress_server, args.controller, egressQueue)  
    except KeyboardInterrupt:
        killSock(signal.SIGINT, None)
