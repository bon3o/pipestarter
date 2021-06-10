FROM ubuntu:18.04
ARG MAIL_PASS
RUN apt update \
    && apt install ca-certificates -y \
    && update-ca-certificates 2>/dev/null || true
COPY pipestarter /usr/local/bin/pipestarter
COPY template.html /etc/pipestarter/
ENV MAIL_PASS=$MAIL_PASS
ENTRYPOINT pipestarter
