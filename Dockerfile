FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 honeypot_user && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin honeypot_user
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY core core
COPY cli cli
COPY main.py config.yaml ./
RUN mkdir data keys && chown honeypot_user:honeypot_user data keys
USER honeypot_user
EXPOSE 2222 8080
STOPSIGNAL SIGTERM
CMD ["python", "main.py"]
