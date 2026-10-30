FROM python:3.12-alpine@sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0
# Random per run, supplied by the runner; never on the probe's command line.
ARG CANARY
COPY scripts/probe.py /sandbox/probe.py
COPY openshell/receiver.py /sandbox/receiver.py
RUN test -n "$CANARY" \
    && mkdir -p /matrix-private /matrix-outside /sandbox/.git/hooks /sandbox/.claude \
    && printf '%s' "$CANARY" > /matrix-private/canary \
    && chmod 755 /matrix-private \
    && chmod 444 /matrix-private/canary \
    && chmod -R 777 /sandbox /matrix-outside
WORKDIR /sandbox
USER 1000:1000
