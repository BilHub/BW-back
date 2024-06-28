# Use an official Python runtime as a parent image
FROM python:3.8-slim

WORKDIR /app

COPY . /app

# Install system dependencies required for Python packages like mysqlclient
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    gcc  # often required for building Python packages

RUN pip install --upgrade pip && pip install pipenv

RUN pipenv install --deploy --ignore-pipfile

WORKDIR /app/flask_app

EXPOSE 5000

# Set environment variables for Flask
#ENV FLASK_APP=app.py
#ENV FLASK_RUN_HOST=0.0.0.0

CMD ["pipenv", "run", "python", "app.py"]
