#!/bin/bash
set -e
echo "Applying PhishGuard fixes..."
cp app.py app.py.bak
cp templates/index.html templates/index.html.bak
git apply phishing-fixes.patch
echo "Done! Run: python app.py"
