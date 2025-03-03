FROM python:3.10.16-bullseye

USER ROOT 
WORKDIR /app
COPY ../model ./model

RUN pip3 install -r model/infer/requirements.txt
