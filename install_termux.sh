#!/data/data/com.termux/files/usr/bin/bash
# ============================================================================
# LoXaSB PRO 5.4 - AUTOMATED TERMUX INSTALLER SCRIPT
# ============================================================================

echo -e "\033[1;32m"
echo "  _          __  __      ____  ____  "
echo " | |    ___  \ \/ / __ _/ ___|| __ ) "
echo " | |   / _ \  \  / / _\` \___ \|  _ \ "
echo " | |__| (_) | /  \| (_| |___) | |_) |"
echo " |_____\___/ /_/\_\\__,_|____/|____/ "
echo -e "\033[0m"
echo -e "\033[1;36m[+] Setting up Go environment for LoXaSB in Termux...\033[0m"

pkg update -y
pkg install golang git traceroute dnsutils -y

# Verify Go installation
if command -v go >/dev/null 2>&1; then
    echo -e "\033[1;32m[✓] Golang is ready: $(go version)\033[0m"
else
    echo -e "\033[1;31m[✗] Go installation failed. Please run: pkg install golang\033[0m"
    exit 1
fi

echo -e "\033[1;33m[+] Compiling LoXaSB Pro Supreme standalone binary...\033[0m"
go build -ldflags="-s -w" -o loxasb loxasb.go
chmod +x loxasb

echo -e "\033[1;32m[✓] Installation complete!\033[0m"
echo -e "\033[1;37mRun LoXaSB anytime with:\033[0m"
echo -e "   \033[1;36m./loxasb\033[0m          (Interactive Menu)"
echo -e "   \033[1;36m./loxasb -t speed.cloudflare.com -trace\033[0m"
echo -e "   \033[1;36m./loxasb -cidr 104.16.0.0/24 -w 8\033[0m"
echo -e "   \033[1;36m./loxasb -f my_hosts.txt -w 10\033[0m"
echo ""

./loxasb
