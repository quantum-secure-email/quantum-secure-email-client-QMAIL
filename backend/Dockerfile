# Use Ubuntu 24.04 as base (matches your WSL environment)
FROM ubuntu:24.04

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    cmake \
    ninja-build \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs from source (required for liboqs-python)
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && \
    cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && \
    ninja install && \
    cd ../.. && \
    rm -rf liboqs

# Update library cache
RUN ldconfig

# Set library path for runtime
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Copy requirements first (for better caching)
COPY requirements.txt .

# Create virtual environment and install Python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Make startup script executable
RUN chmod +x startup.sh

# Expose port (Render will override with its own PORT env var)
EXPOSE 8000

# Set default PORT if not provided by platform
ENV PORT=8000

# Run the startup script
CMD ["./startup.sh"]