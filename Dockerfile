# Official Python multi-platform image, pinned to an immutable manifest index.
ARG PYTHON_BASE=python:3.13-slim-trixie@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
FROM ${PYTHON_BASE} AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
RUN python -m venv --without-pip /opt/venv \
    && python -m pip --python /opt/venv install --no-cache-dir . \
    && python -m pip --python /opt/venv check

FROM ${PYTHON_BASE} AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --gid 65532 cvebeacon \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin cvebeacon \
    && mkdir /config /inventory /state /reports \
    && chown 65532:65532 /state /reports
COPY --from=build /opt/venv /opt/venv
COPY LICENSE NOTICE /usr/share/doc/cvebeacon/
COPY deploy/container/entrypoint.py /opt/cvebeacon-entrypoint.py
WORKDIR /state
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "/opt/cvebeacon-entrypoint.py"]
CMD ["--help"]

FROM build AS extension-build
WORKDIR /extension
COPY extensions/pyproject.toml extensions/README.md extensions/LICENSE extensions/NOTICE ./
COPY extensions/src/ src/
RUN python -m pip --python /opt/venv install --no-cache-dir --no-deps . \
    && python -m pip --python /opt/venv check

FROM runtime AS extensions
COPY --from=extension-build /opt/venv /opt/venv
ENTRYPOINT ["cvebeacon-ext"]
CMD ["--help"]

# Keep the default/final target standalone and free of the companion package.
FROM runtime AS core
