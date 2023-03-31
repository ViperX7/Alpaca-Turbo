FROM python:3.8-slim


# Install pip, cmake and python
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    apt-get clean


RUN apt-get install -y --no-install-recommends curl wget vim git gcc make libc6-dev g++

RUN mkdir -p /app/models

COPY ./requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Set the working directory to /app
WORKDIR /app

# Start the webui.py file when the container is started
CMD python3 /app/api.py & cd angular-turbo;python3 -m http.server 4200
