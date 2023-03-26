FROM python:3.8-slim-buster


# Install pip, cmake and python
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    apt-get clean


RUN apt-get install -y --no-install-recommends curl wget vim
RUN apt-get install -y --no-install-recommends git gcc
RUN apt-get install -y --no-install-recommends make
RUN apt-get install -y --no-install-recommends libc6-dev g++

RUN git clone https://github.com/ViperX7/alpaca.cpp
RUN cd alpaca.cpp/ && make



RUN git clone https://github.com/ViperX7/Alpaca-Turbo /app

RUN pip install --no-cache-dir -r /app/requirements.txt
#
# Copy everything in the app directory to the Docker image
# COPY ./app /app

# Set the working directory to /app
WORKDIR /app


RUN cp /alpaca.cpp/main /app/bin/linux

# Install the Python packages specified in requirements.txt


# Start the webui.py file when the container is started
CMD ["/bin/sh","runindocker.sh"]
