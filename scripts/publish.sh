#!/bin/bash

# Publish Umbrix MCP Server to PyPI

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Publishing Umbrix MCP Server${NC}"

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}❌ Not in umbrix-mcp directory${NC}"
    exit 1
fi

# Clean previous builds
echo -e "${YELLOW}🧹 Cleaning previous builds...${NC}"
rm -rf dist/ build/ *.egg-info

# Build the package
echo -e "${YELLOW}📦 Building package...${NC}"
python -m build

# Check the built package
echo -e "${YELLOW}🔍 Checking package...${NC}"
python -m twine check dist/*

# Upload to PyPI
echo -e "${YELLOW}📤 Uploading to PyPI...${NC}"
echo -e "${YELLOW}   Make sure you have PyPI credentials configured${NC}"
python -m twine upload dist/*

echo -e "${GREEN}✅ Published successfully!${NC}"
echo ""
echo -e "${BLUE}Users can now install with:${NC}"
echo -e "  pip install umbrix-mcp"
echo -e "  uvx install umbrix-mcp"