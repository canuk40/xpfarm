FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install all dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    vim \
    nano \
    tmux \
    gdb \
    gdb-multiarch \
    gdbserver \
    lldb \
    qemu-user \
    qemu-user-static \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    binutils \
    binwalk \
    strace \
    ltrace \
    hexcurse \
    xxd \
    file \
    unzip \
    p7zip-full \
    libcapstone4 \
    libcapstone-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    cmake \
    meson \
    ninja-build \
    libtool \
    autoconf \
    automake \
    netcat \
    socat \
    ripgrep \
    yara \
    ssdeep \
    hashcat \
    clang \
    llvm \
    default-jdk-headless \
    android-tools-adb \
    apktool \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 from official git repository (install to /opt and keep it)
WORKDIR /opt
RUN git clone --depth 1 https://github.com/radareorg/radare2.git && \
    cd radare2 && \
    ./sys/install.sh

# Update library cache after radare2 installation
RUN ldconfig

# Install r2ghidra for better decompilation (optional, may fail)
RUN r2pm -U && (r2pm -ci r2ghidra-dec || echo "r2ghidra installation skipped (optional)") && r2pm -ci r2mcp

# Install JADX for APK decompilation
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip \
    -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm /tmp/jadx.zip

# Install Node.js for OpenCode
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g opencode-ai

# Upgrade pip and setuptools first
RUN pip3 install --upgrade pip setuptools wheel

# Install Python packages for RE, Exploitation, and APK analysis
RUN pip3 install --no-cache-dir r2pipe capstone unicorn frida-tools frida-mcp angr pwntools ropper pycryptodome flare-floss triton-library
RUN pip3 install --no-cache-dir semgrep || echo "semgrep installation skipped (optional)"

# Create working directory for binaries
WORKDIR /workspace

# Create directory for OpenCode configuration
RUN mkdir -p /root/.config/opencode

# Copy OpenCode configuration
COPY config/opencode.json /root/.config/opencode/opencode.json

# Copy custom tools
COPY tools/ /root/.config/opencode/tools/

# Copy YARA rules to expected location
COPY tools/yara-rules/ /opt/yara-rules/

# Create log directory
RUN mkdir -p /workspace/logs && chmod 777 /workspace/logs

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"
ENV TERM=xterm-256color

# Default command
CMD ["/bin/bash"]
