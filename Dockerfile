FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app
RUN python -m pip install --no-cache-dir --only-binary=:all: uv==0.12.23
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY vulntrail ./vulntrail
RUN uv sync --locked --no-dev --no-editable
RUN useradd --uid 10001 --create-home scanner
USER 10001:10001
ENTRYPOINT ["/app/.venv/bin/vulntrail"]
CMD ["--help"]
