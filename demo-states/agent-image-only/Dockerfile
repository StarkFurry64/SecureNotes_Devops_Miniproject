# DEMO DEFECT: outdated, full-size base image with many known HIGH/CRITICAL CVEs.
FROM python:3.8

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only what the app needs (a recursive `COPY . .` is SonarCloud hotspot docker:S6470).
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Run as an unprivileged user instead of root.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=4).status == 200 else 1)"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "app:app"]
