# Separate optional image; the audited root Dockerfile is unchanged.
ARG PYTHON_BASE=python:3.13-slim-trixie@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
FROM ${PYTHON_BASE} AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
COPY extensions/pyproject.toml extensions/README.md extensions/LICENSE extensions/NOTICE extensions/
COPY extensions/src/ extensions/src/
COPY automation/pyproject.toml automation/README.md automation/LICENSE automation/NOTICE automation/
COPY automation/src/ automation/src/
RUN python -m venv --without-pip /opt/venv \
    && python -m pip --python /opt/venv install --no-cache-dir . ./extensions ./automation \
    && python -m pip --python /opt/venv check

FROM ${PYTHON_BASE} AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --gid 65532 cvebeacon \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin cvebeacon \
    && mkdir /config /staging /automation-state /inventory /core-state /reports \
    && chown 65532:65532 /staging /automation-state /inventory /core-state /reports
COPY --from=build /opt/venv /opt/venv
COPY automation/LICENSE automation/NOTICE /usr/share/doc/cvebeacon-automation/
COPY automation/deploy/container/entrypoint.py /opt/automation-entrypoint.py
WORKDIR /automation-state
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "/opt/automation-entrypoint.py"]
CMD ["--help"]
