# Use the official Python image from the Docker Hub, version 3.13-slim
FROM python:3.13-slim

# Update the package list and install supervisor and nano, then clean up the apt cache
RUN apt-get update && \
    apt-get install -y supervisor nano && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the application code from the host to the container
COPY . .

# Install the Python dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 to allow external access to the application
EXPOSE 5000

# Give permission to execute prod/entrypoint.sh
RUN chmod +x prod/entrypoint.sh

# Run the application using the entrypoint.sh script
CMD ["./prod/entrypoint.sh"]
