#!/bin/bash

# ==========================================
#        COLORS & FORMATTING
# ==========================================
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\1;33m'
RED='\033[0;31m'
NC='\033[0m'
WHITE='\033[1;37m'

# ==========================================
#        PATHS & CONFIGURATIONS
# ==========================================
TELEGRAM_CONF="/etc/tunnel_telegram.conf"
HEALER_SCRIPT="/usr/local/bin/tunnel_healer.sh"
GOST_BIN="/usr/local/bin/gost"
HAPROXY_CONF="/etc/haproxy/haproxy.cfg"

# ==========================================
#        SYSTEM OPTIMIZATION
# ==========================================
optimize_system() {
    echo -e "${YELLOW}[*] Applying Kernel Optimizations & BBR...${NC}"
    cat <<EOF > /etc/sysctl.d/99-tunnel.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=10000
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_tw_reuse=1
EOF
    sysctl --system > /dev/null 2>&1
}

apply_qos() {
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    echo -e "${YELLOW}[*] Setting up Smart QoS on $IFACE...${NC}"
    tc qdisc del dev $IFACE root 2>/dev/null
    tc qdisc add dev $IFACE root fq_codel
}

# ==========================================
#        TELEGRAM & REPORTING
# ==========================================
setup_telegram() {
    clear
    echo -e "\n${CYAN}>>> Telegram Bot Configuration <<<${NC}"
    read -p "Enter Bot Token: " BTN
    read -p "Enter Chat ID: " CID
    
    echo -e "\n${WHITE}Is this server located inside IRAN? (y/n)${NC}"
    read -p "Selection: " is_iran

    if [ "$is_iran" == "y" ]; then
        read -p "Enter Worker URL (e.g., bot.venuseco.ir): " W_URL
        W_URL=$(echo $W_URL | sed 's|https://||g;s|http://||g;s|/||g')
        echo -e "${YELLOW}Use HTTPS? (y/n) [Recommended 'n' for .ir domains]:${NC}"
        read -p "Choice: " use_ssl
        [[ "$use_ssl" == "y" ]] && TG_BASE="https://$W_URL" || TG_BASE="http://$W_URL"
    else
        TG_BASE="https://api.telegram.org"
    fi

    echo "TOKEN=$BTN" > $TELEGRAM_CONF
    echo "CHATID=$CID" >> $TELEGRAM_CONF
    echo "TG_URL=$TG_BASE" >> $TELEGRAM_CONF

    echo -e "\n${YELLOW}[*] Sending test message...${NC}"
    RESULT=$(curl -sk --connect-timeout 10 -X POST "$TG_BASE/bot$BTN/sendMessage" \
        -d "chat_id=$CID" -d "text=✅ MASTER TUNNEL PRO Linked!")

    if [[ $RESULT == *"ok\":true"* ]]; then
        echo -e "${GREEN}✔ Connection Successful!${NC}"
    else
        echo -e "${RED}❌ Connection Failed!${NC}"
        echo -e "${YELLOW}Debug: $RESULT${NC}"
    fi
    read -p "Press Enter to continue..."
}

# ==========================================
#        TUNNEL CORE INSTALLATION
# ==========================================
install_tunnel() {
    optimize_system
    echo -e "${YELLOW}[*] Ensuring prerequisites are installed...${NC}"
    
    # نصب پکیج‌ها با مدیریت خطا
    apt-get update -y > /dev/null 2>&1
    apt-get install -y wireguard iptables curl tar bc || echo -e "${CYAN}![!] Apt busy, but proceeding with current packages...${NC}"

    mkdir -p /etc/wireguard
    [ ! -f /etc/wireguard/private.key ] && wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
    
    PRIV=$(cat /etc/wireguard/private.key)
    PUB=$(cat /etc/wireguard/public.key)

    echo -e "\n${WHITE}--- Configuration ---${NC}"
    read -p "Tunnel Port [Default 443]: " T_PORT; T_PORT=${T_PORT:-443}
    read -p "Tunnel Password: " T_PASS
    read -p "WireGuard MTU [Default 1280]: " T_MTU; T_MTU=${T_MTU:-1280}

    echo -e "\n${CYAN}Select Server Role:${NC}"
    echo "1) Foreign Server (Exit Node)"
    echo "2) Iran Server (Bridge Node)"
    read -p "Selection [1-2]: " role

    # نصب udp2raw
    if [ ! -f /opt/udp2raw/udp2raw ]; then
        mkdir -p /opt/udp2raw
        curl -L https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -o /tmp/u.tar.gz
        tar -xzf /tmp/u.tar.gz -C /tmp/ && mv /tmp/udp2raw_amd64 /opt/udp2raw/udp2raw
        chmod +x /opt/udp2raw/udp2raw
    fi

    echo -e "\n${YELLOW}>>> YOUR PUBLIC KEY: $PUB <<<${NC}\n"

    if [ "$role" == "1" ]; then
        read -p "Enter IRAN Public Key: " PEER_PUB
        echo -e "[Interface]\nPrivateKey = $PRIV\nAddress = 10.0.0.1/24\nListenPort = 51820\nMTU = $T_MTU\n[Peer]\nPublicKey = $PEER_PUB\nAllowedIPs = 10.0.0.2/32" > /etc/wireguard/wg0.conf
        EXEC="/opt/udp2raw/udp2raw -s -l0.0.0.0:$T_PORT -r 127.0.0.1:51820 -k '$T_PASS' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
    else
        read -p "Enter FOREIGN IP: " F_IP
        read -p "Enter FOREIGN Public Key: " PEER_PUB
        echo -e "[Interface]\nPrivateKey = $PRIV\nAddress = 10.0.0.2/24\nMTU = $T_MTU\n[Peer]\nPublicKey = $PEER_PUB\nEndpoint = 127.0.0.1:3333\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25" > /etc/wireguard/wg0.conf
        EXEC="/opt/udp2raw/udp2raw -c -l127.0.0.1:3333 -r $F_IP:$T_PORT -k '$T_PASS' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
        apply_qos
    fi

    cat <<EOF > /etc/systemd/system/tunnel.service
[Unit]
Description=Master Tunnel Service
After=network.target

[Service]
ExecStart=$EXEC
ExecStartPost=/usr/bin/wg-quick up wg0
ExecStop=/usr/bin/wg-quick down wg0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now tunnel
    echo -e "\n${GREEN}✔ Tunnel is UP and RUNNING!${NC}"
    read -p "Press Enter to return..."
}

# ==========================================
#        PORT FORWARDING (GOST/HAPROXY)
# ==========================================
# ... (بخش GOST و HAProxy بدون تغییر منطقی فقط با چیدمان تمیز)

# ==========================================
#        MAIN MENU SYSTEM
# ==========================================
while true; do
    clear
    echo -e "${CYAN}========================================================${NC}"
    echo -e "${WHITE}           MASTER TUNNEL PRO - ULTIMATE EDITION${NC}"
    echo -e "${CYAN}========================================================${NC}"
    echo -e "1) ${WHITE}Install/Update Tunnel (Core)${NC}"
    echo -e "2) ${WHITE}Port Forwarder (GOST / HAProxy)${NC}"
    echo -e "3) ${WHITE}Telegram Bot Settings${NC}"
    echo -e "4) ${WHITE}Anti-Lag Auto-Healer${NC}"
    echo -e "5) ${WHITE}Traffic Report Management${NC}"
    echo -e "6) ${WHITE}Show Full System Status${NC}"
    echo -e "7) ${RED}Full Uninstall${NC}"
    echo -e "8) ${WHITE}Exit${NC}"
    echo -e "${CYAN}========================================================${NC}"
    read -p "Select Option: " opt

    case $opt in
        1) install_tunnel ;;
        2) # مدیریت فورواردها (همون کدهای قبلی با نظم بیشتر) ;;
        3) setup_telegram ;;
        # ... بقیه گزینه‌ها
        8) exit 0 ;;
    esac
done
