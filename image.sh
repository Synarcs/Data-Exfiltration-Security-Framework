set -e 

# If the eBPF node agent run inside container, please ensure the container runs in highest privilege mode allowing all kernel privileges to manipulate network functions in kernel 
    # CAP_SYS_ADMIN , CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE, CAP_SYS_ADMIN, CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_SYS_TTY_CONFIG, CAP_SYS_BOOT, CAP_PERFMON, CAP_BPF, CAP_AUDIT_WRITE, CAP_NET_RAW, or preferable CAP_SYS_ADMIN 
# The image except root ns to be either running the inference server in an isolated pid as (unshare --pid --mount-proc --fork), or should be running on root inside the root process with highest privlege
# All the newtwork namespace must be created before and mounted on host, not going to add docker-compose please run on the host as root with privlege mode 

arg=$1 

if [[ $arg == 1 ]]; then 
    docker build --tag exfil_security:latest  .
elif [[ $arg == 2 ]]; then 
    echo "running the eBPF Node Agent in interactive tty shell for build"
    docker run --volume /run:/run --volume $(pwd)/data:/opt/kernel_sec/data -it --rm --privileged exfil_security:latest bash
    if [[ $? -eq 0 ]]; then 
        docker build --no-cache --tag exfil_security:latest  .
    fi 
    docker run -it --rm --privileged exfil_security:latest bash 
else
    echo "option not supported"
fi 
