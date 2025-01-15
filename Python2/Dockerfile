# Use Python 2 base image
FROM python:2.7-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the BinaryCookieReader script into the container
COPY BinaryCookieReader.py /app/BinaryCookieReader.py

# Set the entry point to use the Python interpreter
ENTRYPOINT ["python", "/app/BinaryCookieReader.py"]

