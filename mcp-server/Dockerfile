FROM python:3.12-slim

WORKDIR /app

# Install ripgrep for code search
RUN apt-get update && apt-get install -y \
    ripgrep \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 mcp && chown -R mcp:mcp /app
USER mcp

# Default port
ENV YARMCP_PORT=9742

EXPOSE 9742

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:${YARMCP_PORT}/health || exit 1

CMD ["python", "main.py"]
