FROM maven:latest as build 

# Install Go to compile the k8s netpool install 
ENV GO_VERSION=1.23.0
ENV GOPATH=/go
ARG ARCH=arm64
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Install dependencies and download Go
RUN apt-get update && apt-get install -y curl git && \
    ARCH=$(dpkg --print-architecture | grep -q "arm64" && echo "arm64" || echo "amd64") && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz && \
    apt-get remove -y curl && apt-get autoremove -y && apt-get clean

RUN go version

WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src
COPY cmd ./cmd

RUN mkdir -p bin 
RUN cd cmd && go build -o ../bin/main main.go 
RUN mvn clean package && cp target/node-agent-controller-1.0-SNAPSHOT.jar bin/ && mvn clean 


FROM openjdk:24-ea-17-slim as run

# copy the main controller for the build jar 
COPY --from=build /app/bin/*.jar app.jar
COPY --from=build /app/bin/main main 

EXPOSE 9000
RUN ./main & java -jar app.jar



