from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from typing import NoReturn
import os, sys , socket
import logging , signal

ONNX_INFERENCE_UNIX_SOCKET = "/run/onnx-inference.sock"


log = logging.getLogger(__name__)
log.setLevel(logging.INFO) 
def handleInferenceConn(conn) -> NoReturn:
    print("Conn Received ::", conn)
    while True:
        data = conn.recv(1 << 12)
        print('received connection handled by thread ', data)

    

def killSock(sig, frame) -> None: 
    print(f"Receoved a {sig}, removing the unix socket") 
    os.remove(ONNX_INFERENCE_UNIX_SOCKET) 
    sys.exit(1) 

if __name__ == "__main__":
    if os.path.exists(ONNX_INFERENCE_UNIX_SOCKET):
        os.remove(ONNX_INFERENCE_UNIX_SOCKET) 
    
    try:
        signal.signal(signal.SIGINT, killSock) 

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:

            sock.bind(ONNX_INFERENCE_UNIX_SOCKET) 
            sock.listen(1) 

            with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as pool:
                while True:
                    print("Waiting for inference connection on the Unix Socket") 
                    conn, addr = sock.accept() 
                    pool.submit(handleInferenceConn, (conn,))

    except KeyboardInterrupt as inp:
        killSock( )