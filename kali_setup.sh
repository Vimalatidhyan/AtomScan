#!/bin/bash

###############################################################################
# Technieum Enterprise ASM - Kali Linux Setup Script
# This script installs all dependencies and tools needed for Technieum
# Usage: bash kali_setup.sh
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Technieum Enterprise ASM - Kali Linux Setup${NC}"
echo -e "${BLUE}================================================${NC}\n"

# Function to print section headers
print_header() {
    echo -e "${YELLOW}[*] $1${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

###############################################################################
# Step 1: Update System Packages
###############################################################################
print_header "Step 1: Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
print_success "System packages updated"

###############################################################################
# Step 2: Install System Dependencies
###############################################################################
print_header "Step 2: Installing system dependencies..."

SYSTEM_TOOLS=(
    "python3"
    "python3-pip"
    "python3-venv"
    "python3-dev"
    "build-essential"
    "git"
    "curl"
    "wget"
    "nmap"
    "nikto"
    "masscan"
    "sqlmap"
    "whois"
    "dnsutils"
    "net-tools"
    "netcat"
    "tmux"
    "screen"
    "nano"
    "vim"
    "jq"
    "libssl-dev"
    "libffi-dev"
    "zlib1g-dev"
)

for tool in "${SYSTEM_TOOLS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $tool"; then
        sudo apt-get install -y -qq "$tool" 2>/dev/null || true
        print_success "Installed: $tool"
    else
        print_success "Already installed: $tool"
    fi
done

###############################################################################
# Step 3: Verify Python Version
###############################################################################
print_header "Step 3: Verifying Python version..."
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
print_success "Python version: $PYTHON_VERSION"

if ! command -v python3 &> /dev/null; then
    print_error "Python3 not found! Install it manually and try again."
    exit 1
fi

###############################################################################
# Step 4: Get Project Directory
###############################################################################
print_header "Step 4: Setting up project directory..."
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
print_success "Project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

###############################################################################
# Step 5: Create Python Virtual Environment
###############################################################################
print_header "Step 5: Creating Python virtual environment..."
if [ -d ".venv" ]; then
    print_success "Virtual environment already exists"
else
    python3 -m venv .venv
    print_success "Virtual environment created"
fi

# Activate venv
source .venv/bin/activate
print_success "Virtual environment activated"

###############################################################################
# Step 6: Upgrade pip, setuptools, and wheel
###############################################################################
print_header "Step 6: Upgrading pip and build tools..."
.venv/bin/pip install --upgrade pip setuptools wheel -q
print_success "pip, setuptools, and wheel upgraded"

###############################################################################
# Step 7: Install Python Requirements
###############################################################################
print_header "Step 7: Installing Python requirements..."
if [ -f "requirements.txt" ]; then
    .venv/bin/pip install -r requirements.txt -q
    print_success "All Python packages installed from requirements.txt"
else
    print_error "requirements.txt not found!"
    exit 1
fi

###############################################################################
# Step 8: Verify Key Dependencies
###############################################################################
print_header "Step 8: Verifying key dependencies..."

PYTHON_PACKAGES=(
    "fastapi"
    "uvicorn"
    "sqlalchemy"
    "pydantic"
    "pytest"
    "networkx"
    "requests"
    "pyyaml"
)

for package in "${PYTHON_PACKAGES[@]}"; do
    if .venv/bin/pip show "$package" > /dev/null 2>&1; then
        VERSION=$(.venv/bin/pip show "$package" | grep "Version:" | awk '{print $2}')
        print_success "$package ($VERSION)"
    else
        print_error "$package NOT installed"
    fi
done

###############################################################################
# Step 9: Verify System Tools
###############################################################################
print_header "Step 9: Verifying system tools..."

SYSTEM_CMDS=(
    "nmap"
    "nikto"
    "whois"
    "dig"
    "curl"
    "git"
)

for cmd in "${SYSTEM_CMDS[@]}"; do
    if command -v "$cmd" &> /dev/null; then
        VERSION=$($cmd --version 2>/dev/null | head -1 || echo "installed")
        print_success "$cmd: $VERSION"
    else
        print_error "$cmd NOT found"
    fi
done

###############################################################################
# Step 10: Test API Server
###############################################################################
print_header "Step 10: Testing API server startup..."
timeout 5 .venv/bin/python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 > /dev/null 2>&1 &
UVICORN_PID=$!
sleep 2

if kill -0 $UVICORN_PID 2>/dev/null; then
    print_success "API server starts successfully"
    kill $UVICORN_PID
else
    print_error "API server failed to start"
fi

###############################################################################
# Step 11: Create Auto-Start Script
###############################################################################
print_header "Step 11: Creating auto-start script..."
cat > "$PROJECT_DIR/start_server.sh" << 'EOF'
#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
source .venv/bin/activate
echo "Starting Technieum Enterprise ASM Server..."
echo "Server running at: http://localhost:8000"
echo "Press Ctrl+C to stop"
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
EOF

chmod +x "$PROJECT_DIR/start_server.sh"
print_success "Auto-start script created: start_server.sh"

###############################################################################
# Step 12: Create nohup Start Script
###############################################################################
print_header "Step 12: Creating background start script..."
cat > "$PROJECT_DIR/start_server_bg.sh" << 'EOF'
#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
source .venv/bin/activate
nohup python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 > server.log 2>&1 &
echo $! > server.pid
echo "Server started in background (PID: $(cat server.pid))"
echo "View logs: tail -f server.log"
echo "Stop server: kill $(cat server.pid)"
EOF

chmod +x "$PROJECT_DIR/start_server_bg.sh"
print_success "Background start script created: start_server_bg.sh"

###############################################################################
# Step 13: Create tmux Start Script
###############################################################################
print_header "Step 13: Creating tmux start script..."
cat > "$PROJECT_DIR/start_server_tmux.sh" << 'EOF'
#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="technieum"

# Kill existing session if it exists
tmux kill-session -t $SESSION_NAME 2>/dev/null || true

# Create new session
tmux new-session -d -s $SESSION_NAME -c "$PROJECT_DIR"

# Run server in session
tmux send-keys -t $SESSION_NAME "source .venv/bin/activate && python -m uvicorn api.server:app --host 0.0.0.0 --port 8000" Enter

echo "Server started in tmux session: $SESSION_NAME"
echo "Attach: tmux attach-session -t $SESSION_NAME"
echo "Detach: Ctrl+B then D"
echo "Stop: tmux kill-session -t $SESSION_NAME"
EOF

chmod +x "$PROJECT_DIR/start_server_tmux.sh"
print_success "Tmux start script created: start_server_tmux.sh"

###############################################################################
# Step 14: Create Status Check Script
###############################################################################
print_header "Step 14: Creating status check script..."
cat > "$PROJECT_DIR/check_status.sh" << 'EOF'
#!/bin/bash
echo "=== Technieum Enterprise ASM Status ==="
echo ""
echo "Port 8000 Status:"
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "✓ Server is running on port 8000"
    curl -s http://localhost:8000/api/health | jq . 2>/dev/null || curl -s http://localhost:8000/api/health
else
    echo "✗ Server is NOT running"
fi
echo ""
echo "Virtual Environment:"
if [ -d ".venv" ]; then
    echo "✓ Virtual environment exists"
else
    echo "✗ Virtual environment not found"
fi
echo ""
echo "Log file:"
if [ -f "server.log" ]; then
    echo "Latest 5 lines from server.log:"
    tail -5 server.log
fi
EOF

chmod +x "$PROJECT_DIR/check_status.sh"
print_success "Status check script created: check_status.sh"

###############################################################################
# Step 15: Create Stop Script
###############################################################################
print_header "Step 15: Creating stop script..."
cat > "$PROJECT_DIR/stop_server.sh" << 'EOF'
#!/bin/bash
echo "Stopping Technieum Enterprise ASM Server..."

# Stop from PID file if exists
if [ -f "server.pid" ]; then
    kill $(cat server.pid) 2>/dev/null
    rm server.pid
    echo "Server stopped"
fi

# Stop by port
lsof -ti:8000 | xargs kill -9 2>/dev/null && echo "Killed process on port 8000" || echo "No process found on port 8000"

# Stop tmux session if exists
tmux kill-session -t technieum 2>/dev/null && echo "Killed tmux session: technieum" || true

echo "Done"
EOF

chmod +x "$PROJECT_DIR/stop_server.sh"
print_success "Stop script created: stop_server.sh"

###############################################################################
# Step 16: Summary
###############################################################################
print_header "Step 16: Setup complete!"
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}   Setup Completed Successfully!${NC}"
echo -e "${GREEN}================================================${NC}\n"

echo -e "${BLUE}Quick Start Options:${NC}"
echo ""
echo -e "${YELLOW}1. Foreground (interactive):${NC}"
echo "   bash start_server.sh"
echo ""
echo -e "${YELLOW}2. Background (nohup):${NC}"
echo "   bash start_server_bg.sh"
echo ""
echo -e "${YELLOW}3. Persistent (tmux - recommended):${NC}"
echo "   bash start_server_tmux.sh"
echo ""
echo -e "${YELLOW}4. Check server status:${NC}"
echo "   bash check_status.sh"
echo ""
echo -e "${YELLOW}5. Stop server:${NC}"
echo "   bash stop_server.sh"
echo ""
echo -e "${BLUE}Access Application:${NC}"
echo "   http://localhost:8000"
echo ""
echo -e "${BLUE}Installed Tools:${NC}"
python3 --version
.venv/bin/pip show fastapi | grep Version
.venv/bin/pip show sqlalchemy | grep Version
nmap --version 2>/dev/null | head -1
nikto --version 2>/dev/null | head -1

echo ""
print_success "Ready to use Technieum Enterprise ASM!"
