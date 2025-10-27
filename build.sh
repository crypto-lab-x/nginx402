#!/bin/bash

# Build script for nginx x402 payment module
# This script compiles the dynamic nginx module

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Building nginx x402 payment module ===${NC}"

# Check if nginx source directory exists
if [ -z "$NGINX_SRC" ]; then
    echo -e "${YELLOW}NGINX_SRC environment variable is not set${NC}"
    echo "Attempting to find nginx source path..."
    
    # Try common nginx locations
    if command -v nginx &> /dev/null; then
        NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
        echo -e "${GREEN}Found nginx version: ${NGINX_VERSION}${NC}"
        
        # Try to find nginx source
        for path in "/usr/share/nginx/src" "/usr/src/nginx" "/usr/local/src/nginx" "/tmp/nginx-${NGINX_VERSION}"; do
            if [ -d "$path" ]; then
                NGINX_SRC="$path"
                echo -e "${GREEN}Using nginx source: ${NGINX_SRC}${NC}"
                break
            fi
        done
    fi
    
    if [ -z "$NGINX_SRC" ]; then
        echo -e "${RED}Error: Unable to locate nginx source directory${NC}"
        echo "Please set NGINX_SRC environment variable to nginx source directory"
        echo "Example: export NGINX_SRC=/path/to/nginx-1.18.0"
        echo ""
        echo "Or download nginx source:"
        echo "  wget http://nginx.org/download/nginx-1.18.0.tar.gz"
        echo "  tar -xzf nginx-1.18.0.tar.gz"
        echo "  export NGINX_SRC=\$(pwd)/nginx-1.18.0"
        exit 1
    fi
fi

# Check if NGINX_SRC is valid
if [ ! -d "$NGINX_SRC" ]; then
    echo -e "${RED}Error: NGINX_SRC directory does not exist: ${NGINX_SRC}${NC}"
    exit 1
fi

if [ ! -f "$NGINX_SRC/src/core/ngx_log.h" ]; then
    echo -e "${RED}Error: Invalid nginx source directory: ${NGINX_SRC}${NC}"
    exit 1
fi

echo -e "${GREEN}Using nginx source: ${NGINX_SRC}${NC}"

# Check for required dependencies
echo -e "${GREEN}Checking dependencies...${NC}"

# Check for OpenSSL
if ! pkg-config --exists openssl; then
    echo -e "${RED}Error: OpenSSL development headers not found${NC}"
    echo "Install with: sudo apt-get install libssl-dev (Debian/Ubuntu)"
    echo "              sudo yum install openssl-devel (CentOS/RHEL)"
    echo "              brew install openssl (macOS)"
    exit 1
fi

# Check for curl
if ! pkg-config --exists libcurl; then
    echo -e "${RED}Error: libcurl development headers not found${NC}"
    echo "Install with: sudo apt-get install libcurl4-openssl-dev (Debian/Ubuntu)"
    echo "              sudo yum install libcurl-devel (CentOS/RHEL)"
    echo "              brew install curl (macOS)"
    exit 1
fi

echo -e "${GREEN}All dependencies found${NC}"

# Get nginx version
NGINX_VERSION=$(grep -E "NGINX_VER" $NGINX_SRC/src/core/nginx.h | sed -E 's/.*"([^"]+)".*/\1/')
echo -e "${GREEN}Detected nginx version: ${NGINX_VERSION}${NC}"

# Build configuration
echo -e "${GREEN}Configuring build...${NC}"

NGX_CONFIGURE_ARGS=$(nginx -V 2>&1 | grep -oP 'configure arguments: \K.*')
echo "nginx configure arguments: ${NGX_CONFIGURE_ARGS}"

# Extract module arguments from nginx configure
MODULE_DIR="$(pwd)/src"
OUTPUT_DIR="$(pwd)/modules"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Compile the module
echo -e "${GREEN}Compiling module...${NC}"

# Set environment variables
export NGX_MODULE_CFLAGS="-I${MODULE_DIR}"
export NGX_MODULE_LDFLAGS="-lssl -lcrypto -lcurl"

# Create module compilation command
# Extract compiler flags from nginx
if command -v nginx &> /dev/null; then
    NGX_BUILD_FLAGS=$(nginx -V 2>&1 | grep -oP '--build=\K[^ ]+')
    if [ -z "$NGX_BUILD_FLAGS" ]; then
        NGX_BUILD_FLAGS="-pipe -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g"
    fi
else
    NGX_BUILD_FLAGS="-pipe -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g"
fi

# Build module using nginx auto configuration
if command -v nginx &> /dev/null; then
    # Modern approach: use nginx -V to get build parameters
    nginx -V 2>&1 | grep -oP 'configure arguments: \K.*' > /tmp/nginx_config.txt
    
    # Build module using auto/module
    echo "Building with auto/module..."
    "$NGINX_SRC/auto/module" \
        --add-module="${MODULE_DIR}" \
        --with-cc-opt="-I/usr/include/openssl" \
        --with-ld-opt="-L/usr/lib -lssl -lcrypto -lcurl" \
        || echo "auto/module failed, trying alternative method..."
fi

# Alternative manual compilation
echo -e "${YELLOW}Attempting manual compilation...${NC}"

# Determine nginx binary path for build flags
NGINX_BINARY=$(which nginx)
NGINX_PREFIX=$(dirname $(dirname $NGINX_BINARY))
NGINX_PREFIX=${NGINX_PREFIX:-/usr}

# Get CFLAGS from nginx
eval $(nginx -V 2>&1 | grep -oP 'configure arguments: \K.*' | sed 's/--add-module=/\n/g' | \
    awk '{for(i=1;i<=NF;i++) if ($i ~ /^--with-cc-opt=/) print $i}' | \
    sed 's/--with-cc-opt=/export NGX_CFLAGS="/; s/$/"/')

# Compile source files
echo "Compiling ngx_http_x402_module.c..."
gcc -fPIC -shared \
    -o "${OUTPUT_DIR}/ngx_http_x402_module.so" \
    -I"${NGINX_SRC}/src/core" \
    -I"${NGINX_SRC}/src/http" \
    -I"${NGINX_SRC}/src/http/modules" \
    -I"${NGINX_SRC}/src/event" \
    -I"${NGINX_SRC}/src/os/unix" \
    -I"${NGINX_SRC}/objs" \
    -I"${NGINX_SRC}/src" \
    $(pkg-config --cflags openssl) \
    $(pkg-config --cflags libcurl) \
    $NGX_CFLAGS \
    -std=gnu99 \
    -DNGX_MODULE \
    "${MODULE_DIR}/ngx_http_x402_module.c" \
    "${MODULE_DIR}/ngx_http_x402_utils.c" \
    $(pkg-config --libs openssl) \
    $(pkg-config --libs libcurl) \
    2>&1 | while IFS= read -r line; do
        echo "  $line"
    done

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Module compiled successfully: ${OUTPUT_DIR}/ngx_http_x402_module.so${NC}"
else
    echo -e "${RED}Error: Module compilation failed${NC}"
    
    # Try with simplified compilation for development
    echo -e "${YELLOW}Attempting simplified compilation for development...${NC}"
    
    # This is a simpler approach for development
    OBJ_DIR="${OUTPUT_DIR}/objects"
    mkdir -p "${OBJ_DIR}"
    
    # Compile object files separately
    for file in ngx_http_x402_module.c ngx_http_x402_utils.c; do
        echo "Compiling $file to object file..."
        gcc -fPIC -c \
            -I"${NGINX_SRC}/src/core" \
            -I"${NGINX_SRC}/src/http" \
            -I"${NGINX_SRC}/src/http/modules" \
            -I"${NGINX_SRC}/src/event" \
            -I"${NGINX_SRC}/src/os/unix" \
            -I"${NGINX_SRC}/src" \
            $(pkg-config --cflags openssl) \
            $(pkg-config --cflags libcurl) \
            -std=gnu99 \
            -DNGX_MODULE \
            -o "${OBJ_DIR}/${file%.c}.o" \
            "${MODULE_DIR}/$file"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error compiling $file${NC}"
            exit 1
        fi
    done
    
    # Link into shared library
    gcc -shared \
        -o "${OUTPUT_DIR}/ngx_http_x402_module.so" \
        "${OBJ_DIR}"/*.o \
        $(pkg-config --libs openssl) \
        $(pkg-config --libs libcurl)
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Module compiled successfully: ${OUTPUT_DIR}/ngx_http_x402_module.so${NC}"
        rm -rf "${OBJ_DIR}"
    else
        echo -e "${RED}Error: Module linking failed${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}=== Build Complete ===${NC}"
echo ""
echo "Module file: ${OUTPUT_DIR}/ngx_http_x402_module.so"
echo ""
echo "To install the module in nginx:"
echo "  1. Copy the module to nginx modules directory:"
echo "     sudo cp ${OUTPUT_DIR}/ngx_http_x402_module.so /etc/nginx/modules/"
echo ""
echo "  2. Add to nginx.conf:"
echo "     load_module modules/ngx_http_x402_module.so;"
echo ""
echo "  3. See config/nginx.example for configuration examples"
