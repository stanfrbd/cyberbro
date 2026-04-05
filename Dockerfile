# Use the official Python image from the Docker Hub, version 3.13-slim
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

# Keep root for startup bootstrap tasks (ownership migration), then drop privileges.
USER root

# Runtime UID/GID can be overridden at build time if needed.
ARG APP_UID=1000
ARG APP_GID=1000

# Install gosu for a clean root -> non-root handoff in container entrypoint.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gosu && \
    rm -rf /var/lib/apt/lists/*

# Create an unprivileged runtime user.
RUN groupadd --gid ${APP_GID} cyberbro && \
    useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --home-dir /home/cyberbro --shell /usr/sbin/nologin cyberbro

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the application code from the host to the container
COPY . .

# Install the Python dependencies specified in requirements.txt
RUN uv pip install --system --no-cache-dir -r requirements.txt

# Prepare writable paths and transfer ownership to the non-root user
RUN mkdir -p /var/log/cyberbro /app/data && \
    chown -R cyberbro:cyberbro /app /var/log/cyberbro

# Expose port 5000 to allow external access to the application
EXPOSE 5000

# Give execution permissions to runtime scripts.
RUN chmod +x prod/entrypoint.sh prod/bootstrap.sh prod/fix_ownership.sh

# Run ownership/bootstrap before app startup.
ENTRYPOINT ["./prod/bootstrap.sh"]

# App entrypoint is executed by bootstrap as the unprivileged user.
CMD ["./prod/entrypoint.sh"]
