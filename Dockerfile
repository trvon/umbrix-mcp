FROM python:3.11-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Set up build environment
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Copy dependency files
COPY pyproject.toml .
COPY README.md .

# Install dependencies
RUN uv sync

# Copy source code
COPY src/ ./src/

# Install the project
RUN uv sync --frozen

# Final stage
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 mcpuser

# Copy the application from builder
WORKDIR /app
COPY --from=builder --chown=mcpuser:mcpuser /app /app

# Set up environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"

# Switch to non-root user
USER mcpuser

# Health check (optional)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import umbrix_mcp.server; print('OK')" || exit 1

# Run the MCP server
ENTRYPOINT ["python", "-m", "umbrix_mcp.server"]
