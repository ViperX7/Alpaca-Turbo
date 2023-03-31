FROM python:3.8:slim


# Install pip, cmake and python
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake && \
    apt-get clean


RUN apt-get install -y --no-install-recommends curl wget vim
RUN apt-get install -y --no-install-recommends git gcc
RUN apt-get install -y --no-install-recommends make
RUN apt-get install -y --no-install-recommends libc6-dev g++

# RUN git clone https://github.com/ViperX7/alpaca.cpp
# RUN git clone https://github.com/ViperX7/Alpaca-Turbo /app

RUN mkdir -p /app/models

COPY ./requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# COPY ./alpaca.cpp /alpaca.cpp
# RUN cd alpaca.cpp/ && make
# RUN cp /alpaca.cpp/chat /app/chat

# COPY ./alpaca_turbo.py /app/
# COPY ./api.py /app/
# COPY ./interaction.py /app/
# COPY ./interaction.py /app/
# COPY ./dtype.py /app/

# Copy everything in the app directory to the Docker image
# COPY ./app /app

# Set the working directory to /app
WORKDIR /app



# Install the Python packages specified in requirements.txt


# Start the webui.py file when the container is started
CMD ["python3","/app/api.py"]
