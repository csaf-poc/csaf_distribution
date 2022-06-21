#!/usr/bin/env bash

git clone https://github.com/secvisogram/csaf-validator-service.git

# Install nodejs
curl -fsSL https://deb.nodesource.com/setup_14.x | sudo -E bash -
sudo apt-get install -y nodejs

npm install pm2 -g

cd csaf-validator-service
npm ci
pm2 start npm -- run dev
