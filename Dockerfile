FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.lock /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app/backend
COPY scripts /app/scripts
ENV PYTHONPATH=/app/backend
RUN useradd --create-home sentinel && mkdir /app/.state && chown -R sentinel:sentinel /app
USER sentinel
CMD ["sh", "-c", "python scripts/init_lab.py && uvicorn sentinel.app:app --host 0.0.0.0 --port 8000"]
