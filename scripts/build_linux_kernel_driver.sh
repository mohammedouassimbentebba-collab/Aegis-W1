#!/usr/bin/env bash
# ==============================================================================
# W1™ Linux Kernel Ring-0 Driver & Native C Control Tool Build Script
# File: scripts/build_linux_kernel_driver.sh
# Target: Linux Kernel 5.x / 6.x (x86_64 / arm64)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "${SCRIPT_DIR}/../src/radar_machine_code/linux_kernel" && pwd)"

echo "================================================================================"
echo "🐧 W1™ NATIVE LINUX KERNEL DRIVER & C CONTROLLER BUILD PIPELINE"
echo "================================================================================"
echo "Host Kernel Version: $(uname -r)"
echo "Kernel Source Directory: ${KERNEL_DIR}"
echo ""

# 1. Verify build dependencies (kernel headers and gcc)
echo "🔍 [STEP 1/4] Checking build dependencies..."
if ! command -v gcc &> /dev/null; then
    echo "❌ Error: gcc is required to compile native Linux binaries." >&2
    echo "   Install on Ubuntu/Debian: sudo apt update && sudo apt install -y build-essential linux-headers-\$(uname -r)" >&2
    echo "   Install on RHEL/Fedora  : sudo dnf install -y gcc kernel-devel-\$(uname -r)" >&2
    exit 1
fi

KBUILD_DIR="/lib/modules/$(uname -r)/build"
if [ ! -d "${KBUILD_DIR}" ]; then
    echo "⚠️  Warning: Kernel build headers not found at ${KBUILD_DIR}"
    echo "   Driver module compilation will be skipped; building user-space control tool only."
    BUILD_MODULE=0
else
    BUILD_MODULE=1
fi

# 2. Build User-Space Native C Control Utility (w1_radar_ctl)
echo ""
echo "⚙️  [STEP 2/4] Compiling native C control utility (w1_radar_ctl)..."
cd "${KERNEL_DIR}"
gcc -O3 -Wall -Wextra -D_GNU_SOURCE w1_radar_ctl.c -o w1_radar_ctl -lm
chmod +x w1_radar_ctl
echo "   --> Binary compiled: ${KERNEL_DIR}/w1_radar_ctl"
"${KERNEL_DIR}/w1_radar_ctl" --help || true

# 3. Build Kernel Ring-0 Module (w1_vhf_radar.ko)
if [ "${BUILD_MODULE}" -eq 1 ]; then
    echo ""
    echo "⚙️  [STEP 3/4] Building Ring-0 Kernel Module (w1_vhf_radar.ko)..."
    make -C "${KBUILD_DIR}" M="${KERNEL_DIR}" modules
    echo "   --> Kernel Module compiled: ${KERNEL_DIR}/w1_vhf_radar.ko"

    echo ""
    echo "📦 [STEP 4/4] Kernel Driver Installation Instructions:"
    echo "   1. Insert module into running Linux kernel:"
    echo "      sudo insmod ${KERNEL_DIR}/w1_vhf_radar.ko"
    echo "   2. Verify device node creation in /dev:"
    echo "      ls -l /dev/w1_vhf_radar"
    echo "   3. Inspect kernel dmesg telemetry:"
    echo "      sudo dmesg | grep -i w1_vhf"
    echo "   4. Test hardware communication via native controller:"
    echo "      sudo ${KERNEL_DIR}/w1_radar_ctl status"
else
    echo ""
    echo "⚠️  [STEP 3/4] Skipped kernel module build (missing kernel headers)."
fi

echo ""
echo "================================================================================"
echo "✅ LINUX BUILD PIPELINE COMPLETE: Native C Binaries Ready for Production"
echo "================================================================================"
