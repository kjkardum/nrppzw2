FROM python:3.11-alpine
LABEL author="kjkardum"

WORKDIR app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["gunicorn", "-b", ":8080", "app:app"]