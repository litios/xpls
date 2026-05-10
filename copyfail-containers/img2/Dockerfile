FROM ubuntu:24.04

RUN apt-get update && apt-get install -y vim python3 python3-pip python3-venv

WORKDIR /home/ubuntu

RUN python3 -m venv venv

RUN /home/ubuntu/venv/bin/python3 -m pip install pwntools lief

COPY copyfail-libc.py /home/ubuntu/
ENTRYPOINT ["python3", "-m", "http.server"]