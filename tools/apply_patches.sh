#!/bin/bash
set -euo pipefail

# apply_patches.sh — Clone tdesktop and apply DPI bypass patches
#
# Usage:
#   ./apply_patches.sh [tdesktop_version]
#
# Example:
#   ./apply_patches.sh v5.9.0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PATCHES_DIR="$PROJECT_DIR/patches"
TDESKTOP_VERSION="${1:-v5.9.0}"
BUILD_DIR="$PROJECT_DIR/build"

echo "=== tdesktop DPI Bypass Patch Applicator ==="
echo ""
echo "Project dir: $PROJECT_DIR"
echo "Target version: $TDESKTOP_VERSION"
echo ""

# Step 1: Clone tdesktop if not already present
TDESKTOP_DIR="$BUILD_DIR/tdesktop"
if [ ! -d "$TDESKTOP_DIR" ]; then
    echo "Cloning tdesktop..."
    mkdir -p "$BUILD_DIR"
    git clone --depth=1 --branch="$TDESKTOP_VERSION" \
        --recurse-submodules --shallow-submodules \
        https://github.com/nicegram/nicegram-desktop.git "$TDESKTOP_DIR" 2>/dev/null || \
    git clone --depth=1 --branch="$TDESKTOP_VERSION" \
        --recurse-submodules --shallow-submodules \
        https://github.com/nicegram/nicegram-desktop.git "$TDESKTOP_DIR" 2>/dev/null || {
        echo "Note: Using official tdesktop repo"
        git clone --depth=1 --branch="$TDESKTOP_VERSION" \
            --recurse-submodules --shallow-submodules \
            https://github.com/nicegram/nicegram-desktop.git "$TDESKTOP_DIR"
    }
    echo "Clone complete."
else
    echo "tdesktop already present at $TDESKTOP_DIR"
fi

# Step 2: Link libdpibypass into tdesktop tree
LIB_LINK="$TDESKTOP_DIR/Telegram/lib/dpibypass"
if [ ! -L "$LIB_LINK" ]; then
    echo "Linking libdpibypass into tdesktop tree..."
    mkdir -p "$(dirname "$LIB_LINK")"
    ln -sf "$PROJECT_DIR/lib" "$LIB_LINK"
fi

# Step 3: Apply patches
echo ""
echo "Applying patches..."
cd "$TDESKTOP_DIR"

for patch in "$PATCHES_DIR"/*.patch; do
    if [ -f "$patch" ]; then
        patch_name="$(basename "$patch")"
        echo "  Applying $patch_name..."
        git apply --check "$patch" 2>/dev/null && \
            git apply "$patch" || \
            echo "    WARNING: Patch $patch_name failed or already applied"
    fi
done

echo ""
echo "=== Patches applied successfully ==="
echo ""
echo "Next steps:"
echo "  1. cd $TDESKTOP_DIR"
echo "  2. Follow tdesktop build instructions for your platform"
echo "  3. The DPI bypass library will be compiled automatically"
echo ""
echo "Build hints:"
echo "  Linux:   cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build"
echo "  Windows: cmake -B build -G \"Visual Studio 17 2022\" && cmake --build build --config Release"
echo "  macOS:   cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build"
