## Control Plane compilation steps and deploying instructions at the controller servers.


### Infrastructure Requriements at Controller server.
* Since the controller server runs entirely in userspace, it can be ran on any infrastructure, irrespective of whether running Linux kernel internally, however, the framework primarily developed for server environments running on Linux to stop DNS advanced attacks, the installation steps assume the controller server runs ubuntu.
    * The controller server is entirely build using Spring Boot
    * Internally relies on Spring-Kafka, Spring-Hibernate to connect to PowerDNS server backend.


### Clone the repository on controller server.
```
    git clone https://github.com/Synarcs/DNSObelisk
    cd DNSObelisk
```

### Install dependencies
```
    sudo apt update && sudo apt-get install build-essential 
    make build-dep-controller 
```

### Build the controller JAR
```
    make build-controller 
```

### Start prometheus node-exporters at endpoint for endpoint resource monitoring 
```
    make node-metrics
```

### modify the Java Spring PowerDNS backend config, spring server and Kafka broker connection config to point to correct endpoints 
**controller/src/main/application.yml**, **controller/src/main/config.yaml**

### start the controller server
```
    make run-controller
```

### verify controller running on configured port
```
    curl --head -X GET $(IP):$(PORT)/version 
```