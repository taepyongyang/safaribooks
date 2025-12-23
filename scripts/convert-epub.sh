#!/bin/bash
#
# convert-epub.sh - Convert EPUB to MOBI and back to clean EPUB
#
# This script uses Calibre's ebook-convert to clean up EPUBs by converting
# through MOBI format, which often fixes formatting issues.
#
# Usage:
#   convert-epub.sh [epub_file]
#
# If no file is specified, looks for a single *.epub file in the current directory.
#
# Examples:
#   cd Books/Visualizing\ Generative\ AI\ \(9781098172299\)/
#   ../../scripts/convert-epub.sh
#
#   scripts/convert-epub.sh "Books/Some Book/book.epub"
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if ebook-convert is available
if ! command -v ebook-convert &> /dev/null; then
    echo -e "${RED}Error: ebook-convert not found${NC}"
    echo "Please install Calibre: https://calibre-ebook.com/download"
    exit 1
fi

# Determine input file
if [ -n "$1" ]; then
    # Parameter provided - use it
    EPUB_FILE="$1"

    if [ ! -f "$EPUB_FILE" ]; then
        echo -e "${RED}Error: File not found: $EPUB_FILE${NC}"
        exit 1
    fi
else
    # No parameter - find single *.epub in current directory
    EPUB_COUNT=$(find . -maxdepth 1 -name "*.epub" -type f | wc -l | tr -d ' ')

    if [ "$EPUB_COUNT" -eq 0 ]; then
        echo -e "${RED}Error: No .epub files found in current directory${NC}"
        echo "Usage: $0 [epub_file]"
        exit 1
    elif [ "$EPUB_COUNT" -gt 1 ]; then
        echo -e "${RED}Error: Multiple .epub files found in current directory${NC}"
        echo "Please specify which file to convert:"
        find . -maxdepth 1 -name "*.epub" -type f
        exit 1
    fi

    EPUB_FILE=$(find . -maxdepth 1 -name "*.epub" -type f)
fi

# Get the base name without extension
BASENAME="${EPUB_FILE%.epub}"
MOBI_FILE="${BASENAME}.mobi"
FINAL_EPUB="${BASENAME}.final.epub"

echo -e "${YELLOW}Converting: $EPUB_FILE${NC}"
echo ""

# Step 1: Convert EPUB to MOBI
echo -e "${GREEN}[1/2] Converting EPUB to MOBI...${NC}"
ebook-convert "$EPUB_FILE" "$MOBI_FILE"
echo ""

# Step 2: Convert MOBI back to EPUB
echo -e "${GREEN}[2/2] Converting MOBI to clean EPUB...${NC}"
ebook-convert "$MOBI_FILE" "$FINAL_EPUB"
echo ""

# Report success
echo -e "${GREEN}Done!${NC}"
echo ""
echo "Files created:"
echo "  MOBI:  $MOBI_FILE"
echo "  EPUB:  $FINAL_EPUB"
