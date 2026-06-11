# Multi-stage build for The Mirror agent
# Stage 1: Build dependencies
FROM registry.access.redhat.com/ubi9/python-311:latest AS builder

USER root

# Install build dependencies
RUN dnf install -y gcc python3-devel && dnf clean all

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Stage 2: Runtime image
FROM registry.access.redhat.com/ubi9/python-311:latest

USER root

# Install runtime system packages (bind-utils for DNS lookups)
# Note: whois command can be implemented via Python or API calls instead
RUN dnf install -y bind-utils && dnf clean all

# Use existing default user (UID 1001 already exists in UBI Python image)
# No need to create a new user

# Copy Python dependencies from builder stage
COPY --from=builder /opt/app-root /opt/app-root

# Set working directory
WORKDIR /app

# Copy application code
COPY agent/ /app/agent/
COPY osint-modules/ /app/osint-modules/
COPY templates/ /app/templates/
COPY action-pool.yaml /app/action-pool.yaml
COPY suspicious-user-agents.yaml /app/suspicious-user-agents.yaml
COPY audit-log-schema.json /app/audit-log-schema.json

# Create directories for logs and evidence (will be overridden by volumes in K8s)
RUN mkdir -p /var/log/cyber-riposte/evidence /var/log/cyber-riposte/postmortems && \
    chown -R 1001:0 /app /var/log/cyber-riposte && \
    chmod -R g=u /app /var/log/cyber-riposte

# Switch to non-root user
USER 1001

# Set Python path
ENV PYTHONPATH=/app
ENV PATH="/opt/app-root/bin:${PATH}"

# Expose health check port
EXPOSE 8080

# Run the agent
CMD ["python3", "-m", "agent.main"]
