import shutil
import subprocess
import logging
import sys
import os
import platform

# Configuration
TOOLS_DIR = os.path.join(os.getcwd(), "tools")
BIN_DIR = os.path.join(os.getcwd(), "bin")

# Ensure directories exist
os.makedirs(TOOLS_DIR, exist_ok=True)
os.makedirs(BIN_DIR, exist_ok=True)

# Tool Definitions
TOOLS = {
    "nmap": {
        "type": "system",
    },
    "nuclei": {
        "type": "go",
        "cmd": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "gowitness": {
        "type": "go",
        "cmd": "github.com/sensepost/gowitness@latest",
    },
    "ffuf": {
        "type": "go_build", 
        "repo": "https://github.com/ffuf/ffuf",
    },
    "findomain": {
        "type": "cargo",
        "repo": "https://github.com/Findomain/Findomain",
        "bin_path": "target/release/findomain",
    }
}

def check_path(tool_name):
    """Check if tool is in system PATH or local bin."""
    # Check local bin first
    local_bin = os.path.join(BIN_DIR, tool_name)
    if os.path.exists(local_bin):
        return local_bin
    if platform.system() == "Windows":
        if os.path.exists(local_bin + ".exe"):
            return local_bin + ".exe"
            
    return shutil.which(tool_name)

def install_system_advice(tool_name, logger):
    system = platform.system().lower()
    if system == "linux":
        # Check for distros roughly
        if shutil.which("apt"):
            cmd = "sudo apt install nmap"
        elif shutil.which("pacman"):
            cmd = "sudo pacman -S nmap"
        else:
            cmd = "sudo yum install nmap" # Generic
    elif system == "darwin": # Mac
        cmd = "brew install nmap"
    else: # Windows/Other
        cmd = "download installer from https://nmap.org/download.html"
        
    logger.critical(f"[bold red]{tool_name} not found![/] Please install it manually.")
    logger.critical(f"Suggested command: [bold cyan]{cmd}[/]")
    sys.exit(1) # As per request "If nmap is not installed then print to install it... depending on system". Implicitly stop or fallback? 
    # User said "If nmap is not installed then print to install it...". 
    # User also said "For the remaining tools, install them from source". Nmap was separated.
    # So we probably shouldn't fallback to docker for nmap if the goal is system install advice.
    
def check_runtime(runtime, logger):
    if not shutil.which(runtime):
        logger.warning(f"Runtime [bold yellow]{runtime}[/] not found.")
        return False
    return True

def install_go(tool_name, config, logger):
    logger.info(f"Installing [cyan]{tool_name}[/] via Go...")
    try:
        # GOBIN to our local bin
        env = os.environ.copy()
        env["GOBIN"] = BIN_DIR
        subprocess.run(["go", "install", "-v", config["cmd"]], env=env, check=True)
        logger.info(f"Successfully installed {tool_name} to {BIN_DIR}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Go install failed for {tool_name}: {e}")
        return False

def install_go_build(tool_name, config, logger):
    # For ffuf "go get ; go build" style implies cloning first
    logger.info(f"Building [cyan]{tool_name}[/] from source (Go)...")
    repo_path = os.path.join(TOOLS_DIR, tool_name)
    
    try:
        if not os.path.exists(repo_path):
            subprocess.run(["git", "clone", config["repo"], repo_path], check=True)
        
        # Build
        subprocess.run(["go", "get"], cwd=repo_path, check=True)
        subprocess.run(["go", "build"], cwd=repo_path, check=True)
        
        # Move binary to BIN_DIR
        src_bin = os.path.join(repo_path, tool_name)
        if platform.system() == "Windows":
            src_bin += ".exe"
            
        dst_bin = os.path.join(BIN_DIR, tool_name)
        if platform.system() == "Windows":
            dst_bin += ".exe"
            
        shutil.copy2(src_bin, dst_bin)
        logger.info(f"Built and installed {tool_name}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Go build failed for {tool_name}: {e}")
        return False

def install_cargo(tool_name, config, logger):
    logger.info(f"Building [cyan]{tool_name}[/] from source (Rust)...")
    repo_path = os.path.join(TOOLS_DIR, tool_name)
    
    try:
        if not os.path.exists(repo_path):
            subprocess.run(["git", "clone", config["repo"], repo_path], check=True)
            
        # Build
        subprocess.run(["cargo", "build", "--release"], cwd=repo_path, check=True)
        
        # Copy binary
        src_bin = os.path.join(repo_path, config["bin_path"]) # e.g. target/release/findomain
        if platform.system() == "Windows":
             src_bin += ".exe"

        dst_bin = os.path.join(BIN_DIR, tool_name)
        if platform.system() == "Windows":
             dst_bin += ".exe"
             
        shutil.copy2(src_bin, dst_bin)
        logger.info(f"Built and installed {tool_name}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Cargo build failed for {tool_name}: {e}")
        return False


# ----- Environment Checks -----
def check_environment(logger):
    """Check for required runtimes (Get)."""
    missing = []
    if not shutil.which("go"):
        missing.append("go")
    # Rust check removed as per request
    
    if missing:
        logger.critical(f"[bold red]Missing required runtimes: {', '.join(missing)}[/]")
        logger.critical("Please install Go to proceed.")
        sys.exit(1)

def ensure_tool(tool_name, logger):
    config = TOOLS[tool_name]
    
    # 1. Check Path
    path = check_path(tool_name)
    if path:
        logger.info(f"Found [bold green]{tool_name}[/] at {path}")
        return "local"
        
    logger.warning(f"[bold yellow]{tool_name}[/] not found locally.")
    
    # 2. System Install Advice (Nmap)
    if config["type"] == "system":
        install_system_advice(tool_name, logger)
        return "missing"

    # 3. Source Install
    installed = False
    if config["type"] == "go":
        installed = install_go(tool_name, config, logger)
    elif config["type"] == "go_build": # legacy support if needed
        installed = install_go_build(tool_name, config, logger)
    elif config["type"] == "cargo":
        installed = install_cargo(tool_name, config, logger)
            
    if installed:
        return "local" # Now it's local in BIN_DIR
        
    logger.critical(f"[bold red]Failed to setup {tool_name}[/]")
    return None

def verify_tools(logger):
    # Add local bin to path for this session
    os.environ["PATH"] += os.pathsep + BIN_DIR
    
    # Pre-flight check
    check_environment(logger)
    
    status = {}
    for tool in TOOLS:
        res = ensure_tool(tool, logger)
        if res is None:
            sys.exit(1)
        status[tool] = res
    return status
