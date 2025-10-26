FROM python:3.12-slim


# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
build-essential \
&& rm -rf /var/lib/apt/lists/*


WORKDIR /app


# Install deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt


# App code
COPY app ./app
COPY modules ./modules


# Data dir for SQLite
VOLUME ["/data"]
ENV DB_PATH=/data/ctf.db


EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
