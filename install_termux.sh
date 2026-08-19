#!/data/data/com.termux/files/usr/bin/bash
# ============================================================================
# LoXaSB PRO 5.5 - BUGSCAN-X NATIVE GO ENGINE (AUTOMATED TERMUX INSTALLER)
# Repository: https://github.com/roxasblessed403-design/LoXaS.git
# Global Commands: 'loxas' and 'lx'
# ============================================================================

echo -e "\033[1;32m"
echo "  _          __  __      ____  ____  "
echo " | |    ___  \ \/ / __ _/ ___|| __ ) "
echo " | |   / _ \  \  / / _\` \___ \|  _ \ "
echo " | |__| (_) | /  \| (_| |___) | |_) |"
echo " |_____\___/ /_/\_\\__,_|____/|____/ "
echo -e "\033[0m"
echo -e "\033[1;36m[+] Setting up Go & Git environment for LoXaSB in Termux...\033[0m"

pkg update -y
pkg install golang git traceroute dnsutils -y

# Verify Go installation
if command -v go >/dev/null 2>&1; then
    echo -e "\033[1;32m[✓] Golang is ready: $(go version)\033[0m"
else
    echo -e "\033[1;31m[✗] Go installation failed. Please run: pkg install golang\033[0m"
    exit 1
fi

# Fetch repository or script if not present
if [ ! -f "loxasb.go" ]; then
    echo -e "\033[1;33m[+] Fetching LoXaSB from GitHub (roxasblessed403-design/LoXaS)...\033[0m"
    if [ -d ".git" ]; then
        git pull
    else
        git clone https://github.com/roxasblessed403-design/LoXaS.git
        cd LoXaS 2>/dev/null || true
    fi
fi

echo -e "\033[1;33m[+] Compiling LoXaSB Pro Supreme standalone binary...\033[0m"
go build -ldflags="-s -w" -o loxasb loxasb.go
chmod +x loxasb

# Install globally to $PREFIX/bin as 'loxas' and 'lx'
echo -e "\033[1;33m[+] Installing global shortcuts: 'loxas' and 'lx'...\033[0m"
rm -f $PREFIX/bin/loxas $PREFIX/bin/lx 2>/dev/null || true
cp loxasb $PREFIX/bin/loxas 2>/dev/null || cp loxasb /data/data/com.termux/files/usr/bin/loxas 2>/dev/null || true
cp loxasb $PREFIX/bin/lx 2>/dev/null || cp loxasb /data/data/com.termux/files/usr/bin/lx 2>/dev/null || true
chmod +x $PREFIX/bin/loxas $PREFIX/bin/lx 2>/dev/null || true

echo -e "\033[1;32m[✓] Installation complete!\033[0m"
echo -e "\033[1;37mYou can now run LoXaSB from ANY directory using:\033[0m"
echo -e "   \033[1;32mloxas\033[0m   or   \033[1;32mlx\033[0m"
echo ""

loxas
