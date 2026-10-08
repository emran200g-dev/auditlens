FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
# Pre-install the compilers Slither needs so scans never depend on a runtime download
RUN for v in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.24; do solc-select install $v; done && solc-select use 0.8.24
COPY . .
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
