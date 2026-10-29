FROM python:3.12-alpine@sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0
COPY scripts/probe.py /sandbox/probe.py
COPY openshell/receiver.py /sandbox/receiver.py
RUN mkdir -p /matrix-private /matrix-outside \
    && printf SANDBOX_MATRIX_SYNTHETIC_ONLY > /matrix-private/canary \
    && chmod 755 /matrix-private \
    && chmod 444 /matrix-private/canary \
    && chmod 777 /sandbox /matrix-outside
WORKDIR /sandbox
USER 1000:1000
