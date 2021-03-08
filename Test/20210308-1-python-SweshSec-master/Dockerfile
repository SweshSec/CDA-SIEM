FROM python:3.8.0

COPY . /opt/api

WORKDIR /opt/api

USER root

RUN pip3 install --require-hashes -r requirements.txt

CMD APP_ENV=production python3 ./main.py