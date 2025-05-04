# Use official Python base image
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y nmap && \
    apt-get clean

# Set working directory
WORKDIR /app

# Copy all files into the container
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt.txt

# Set default command for CI mode
CMD ["python", "main.py", "--ci"]
