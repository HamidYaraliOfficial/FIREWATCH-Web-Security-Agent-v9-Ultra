FROM mcr.microsoft.com/playwright/python:1.63.0-noble
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright PYTHONPATH=/app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin firewatch
COPY backend/app ./app
COPY backend/tests ./tests
COPY frontend ./frontend
COPY scripts ./scripts
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
RUN mkdir -p /data/reports /data/.firewatch \
 && chown -R firewatch:firewatch /app /data
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
