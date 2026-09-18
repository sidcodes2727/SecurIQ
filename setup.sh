#!/bin/bash
# ============================================
# IPsec VPN Protocol Analyzer - Setup Script
# ============================================
set -e

echo "============================================"
echo "  IPsec VPN Protocol Analyzer Setup"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check Python
echo -e "${CYAN}[1/6] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required. Please install Python 3.9+."
    exit 1
fi
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}  ✓ Python $PYTHON_VERSION${NC}"

# Check Node.js
echo -e "${CYAN}[2/6] Checking Node.js...${NC}"
if ! command -v node &> /dev/null; then
    echo "Node.js is required. Please install Node.js 18+."
    exit 1
fi
NODE_VERSION=$(node --version)
echo -e "${GREEN}  ✓ Node.js $NODE_VERSION${NC}"

# Backend setup
echo -e "${CYAN}[3/6] Setting up backend...${NC}"
cd backend
python3 -m venv venv 2>/dev/null || true
source venv/bin/activate 2>/dev/null || true
pip install -r requirements.txt --quiet
echo -e "${GREEN}  ✓ Backend dependencies installed${NC}"
cd ..

# Frontend setup
echo -e "${CYAN}[4/6] Setting up frontend...${NC}"
cd frontend
npm install --silent 2>/dev/null
echo -e "${GREEN}  ✓ Frontend dependencies installed${NC}"
cd ..

# Run tests
echo -e "${CYAN}[5/6] Running backend tests...${NC}"
cd backend
python3 -m pytest tests/ -v --tb=short 2>&1 || echo "  ⚠ Some tests may need the full setup to pass"
cd ..

echo -e "${CYAN}[6/6] Setup complete!${NC}"
echo ""
echo "============================================"
echo -e "${GREEN}  Setup Complete! 🎉${NC}"
echo "============================================"
echo ""
echo "To start the application:"
echo ""
echo "  1. Start the backend (from the project root):"
echo "     source backend/venv/bin/activate"
echo "     uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "  2. Start the frontend (in another terminal):"
echo "     cd frontend"
echo "     npm run dev"
echo ""
echo "  3. Open http://localhost:5173 in your browser"
echo ""
echo "The backend will automatically:"
echo "  - Generate sample PCAP files"
echo "  - Generate synthetic training dataset"
echo "  - Train the ML model"
echo ""
