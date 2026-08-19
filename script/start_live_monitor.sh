#!/bin/bash
# K-Guard Live Monitor Startup Script

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     K-Guard Live Security Monitor         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo -e "${GREEN}✓${NC} Virtual environment activated"
else
    echo -e "${YELLOW}⚠${NC} No virtual environment found"
fi

# Check if Flask-SocketIO is installed
if ! python3 -c "import flask_socketio" 2>/dev/null; then
    echo -e "${RED}✗${NC} Flask-SocketIO not found"
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r requirements.txt
fi

# Check if monitor binary exists
if [ ! -f "./monitor" ]; then
    echo -e "${RED}✗${NC} monitor binary not found"
    echo -e "${YELLOW}Run 'make' to build the monitor first${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Dependencies verified"
echo ""
echo -e "${YELLOW}Starting K-Guard Live Monitor...${NC}"
echo -e "${GREEN}➜${NC} Dashboard: ${GREEN}http://localhost:5000${NC}"
echo -e "${YELLOW}➜${NC} Press Ctrl+C to stop"
echo ""

# Start the monitor and live engine
sudo ./monitor | python3 src/user/graphengine_live.py
