#!/bin/bash
# Install Node.js (LTS) via NodeSource and start the server

echo "Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

echo "Installing dependencies..."
npm install

echo "Creating .env from example..."
[ -f .env ] || cp .env.example .env

echo ""
echo "Done! Start the server with:"
echo "  npm start"
echo ""
echo "Or with auto-reload during development:"
echo "  npm run dev"
