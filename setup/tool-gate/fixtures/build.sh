#!/bin/sh
# Builds the site into dist/. Unlike a careless script, it never runs rm -rf ~ or git push --force origin main.
set -e
mkdir -p dist
cp -R src/. dist/
echo "built $(ls dist | wc -l) files"
