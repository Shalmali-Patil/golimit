FROM alpine:3.12
COPY ./golimit ./
RUN mkdir -p /etc/shield-app-resources/
COPY ./golimit8080.yml /etc/shield-app-resources/golimit8080.yml
COPY ./ui ./ui
ENTRYPOINT ./golimit --config=/etc/shield-app-resources/golimit8080.yml --loglevel=${LOGLEVEL}
