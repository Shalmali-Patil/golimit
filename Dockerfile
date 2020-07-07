FROM alpine:3.12
COPY ./golimit ./
COPY ./golimit8080.yml ./
COPY ./ui ./ui
ENTRYPOINT ./golimit --config=./golimit8080.yml --loglevel=${LOGLEVEL}
