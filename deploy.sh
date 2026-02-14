#!/bin/bash

# --- Colors ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
WHITE='\033[1;37m'

# --- Config Paths ---
TELEGRAM_CONF="/etc/tunnel_telegram.conf"
HEALER_SCRIPT="/usr/local/bin/tunnel_healer.sh"
GOST_BIN="/usr/local/bin/gost"
HAPROXY_CONF="/etc/haproxy/haproxy.cfg"

# --- 1. Optimization ---
optimize_system() {
    echo -e "${YELLOW}[*] Applying Kernel Optimizations & BBR...${NC}"
    cat <<EOF > /etc/sysctl.d/99-tunnel.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=67108864
net.core.wmem_max=67108864
EOF
    sysctl --system > /dev/null 2>&1
}

apply_qos() {
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    tc qdisc del dev $IFACE root 2>/dev/null
    tc qdisc add dev $IFACE root fq_codel
}

# --- 2. Telegram Settings ---
setup_telegram() {
    clear
    echo -e "\n${CYAN}>>> Telegram Bot Configuration <<<${NC}"
    read -p "Enter Bot Token: " BTN
    read -p "Enter Chat ID: " CID
    echo -ne "Inside Iran? (y/n): "; read is_iran
    if [ "$is_iran" == "y" ]; then
        read -p "Worker URL (e.g. bot.venuseco.ir): " W_URL
        W_URL=$(echo $W_URL | sed 's|https://||g;s|http://||g;s|/||g')
        read -p "Use HTTPS? (y/n) [n is recommended]: " use_ssl
        [[ "$use_ssl" == "y" ]] && TG_BASE="https://$W_URL" || TG_BASE="http://$W_URL"
    else
        TG_BASE="https://api.telegram.org"
    fi
    echo -e "TOKEN=$BTN\nCHATID=$CID\nTG_URL=$TG_BASE" > $TELEGRAM_CONF
    echo -e "${YELLOW}[*] Testing connection...${NC}"
    RESULT=$(curl -sk --connect-timeout 10 -X POST "$TG_BASE/bot$BTN/sendMessage" -d "chat_id=$CID" -d "text=✅ MASTER TUNNEL PRO Connected!")
    [[ $RESULT == *"ok\":true"* ]] && echo -e "${GREEN}✔ Linked!${NC}" || echo -e "${RED}❌ Error: $RESULT${NC}"
    read -p "Press Enter..."
}

# --- 3. Auto-Healer ---
setup_auto_healer() {
    touch /etc/tunnel_reset_count /etc/total_down /etc/total_up
    chmod 666 /etc/tunnel_reset_count /etc/total_down /etc/total_up
    cat <<'EOF' > $HEALER_SCRIPT
#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[ -f /etc/tunnel_telegram.conf ] && source /etc/tunnel_telegram.conf
TARGET="10.0.0.1"; grep -q "10.0.0.1" /etc/wireguard/wg0.conf && TARGET="10.0.0.2"
check_conn() {
    for i in {1..3}; do ping -c 1 -W 3 $TARGET >/dev/null 2>&1 && return 0; sleep 2; done; return 1
}
if ! check_conn; then
    S=$(wg show wg0 transfer 2>/dev/null)
    D=$(echo $S | awk '{print $2}' | sed 's/[^0-9]//g'); U=$(echo $S | awk '{print $5}' | sed 's/[^0-9]//g')
    [ -n "$D" ] && echo $(( $(cat /etc/total_down 2>/dev/null || echo 0) + D )) > /etc/total_down
    [ -n "$U" ] && echo $(( $(cat /etc/total_up 2>/dev/null || echo 0) + U )) > /etc/total_up
    systemctl stop tunnel; wg-quick down wg0; ip link delete wg0 2>/dev/null; systemctl start tunnel; sleep 5; wg-quick up wg0
    C=$(cat /etc/tunnel_reset_count 2>/dev/null || echo 0); echo $((C + 1)) > /etc/tunnel_reset_count
    [ -n "$TOKEN" ] && curl -sk -X POST "$TG_URL/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=🚨 Auto-Heal Done on $(hostname)" >/dev/null 2>&1
fi
EOF
    chmod +x $HEALER_SCRIPT
    (crontab -l 2>/dev/null | grep -v "tunnel_healer.sh"; echo "* * * * * $HEALER_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Healer Active.${NC}"
}

# --- 4. Main Menu Case ---
while true; do
    clear
   echo -e "${CYAN}========================================================"
    echo -e "${CYAN}██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo -e "╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo -e " ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo -e "  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo -e "   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo -e "   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${WHITE}               [ MASTER TUNNEL PRO v2.00 ]${NC}"
    echo -e "${CYAN}========================================================${NC}"
    echo "1) Install/Update Tunnel"
    echo "2) Port Forwarder (GOST/HAProxy)"
    echo "3) Telegram Bot Settings"
    echo "4) Anti-Lag Auto-Healer"
    echo "5) Daily Traffic Report"
    echo "6) System Status"
    echo "7) Uninstall"
    echo "8) Exit"
    read -p "Select: " opt

    case $opt in
        1)
            optimize_system
            apt-get install -y wireguard iptables curl tar bc || echo "Apt busy, proceeding..."
            mkdir -p /etc/wireguard
            [ ! -f /etc/wireguard/private.key ] && wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
            MY_PUB=$(cat /etc/wireguard/public.key); MY_PRIV=$(cat /etc/wireguard/private.key)
            read -p "Tunnel Port [443]: " T_PORT; T_PORT=${T_PORT:-443}
            read -p "Password: " T_PASS; read -p "MTU [1280]: " T_MTU; T_MTU=${T_MTU:-1280}
            echo -e "1) Foreign\n2) Iran"; read -p "Role: " role
            [ ! -d /opt/udp2raw ] && mkdir -p /opt/udp2raw && curl -L https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -o /tmp/u.tar.gz && tar -xzf /tmp/u.tar.gz -C /tmp/ && mv /tmp/udp2raw_amd64 /opt/udp2raw/udp2raw && chmod +x /opt/udp2raw/udp2raw
            if [ "$role" == "1" ]; then
                read -p "Iran PubKey: " PEER_PUB
                echo -e "[Interface]\nPrivateKey = $MY_PRIV\nAddress = 10.0.0.1/24\nListenPort = 51820\nMTU = $T_MTU\n[Peer]\nPublicKey = $PEER_PUB\nAllowedIPs = 10.0.0.2/32" > /etc/wireguard/wg0.conf
                EXEC="/opt/udp2raw/udp2raw -s -l0.0.0.0:$T_PORT -r 127.0.0.1:51820 -k '$T_PASS' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
            else
                read -p "Foreign IP: " F_IP; read -p "Foreign PubKey: " PEER_PUB
                echo -e "[Interface]\nPrivateKey = $MY_PRIV\nAddress = 10.0.0.2/24\nMTU = $T_MTU\n[Peer]\nPublicKey = $PEER_PUB\nEndpoint = 127.0.0.1:3333\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25" > /etc/wireguard/wg0.conf
                EXEC="/opt/udp2raw/udp2raw -c -l127.0.0.1:3333 -r $F_IP:$T_PORT -k '$T_PASS' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
                apply_qos
            fi
            cat <<EOF > /etc/systemd/system/tunnel.service
[Unit]
After=network.target
[Service]
ExecStart=$EXEC
ExecStartPost=/usr/bin/wg-quick up wg0
ExecStop=/usr/bin/wg-quick down wg0
Restart=always
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload && systemctl enable --now tunnel
            echo -e "${GREEN}✔ Tunnel Started.${NC}"; read -p "Press Enter..."
            ;;
        2)
            echo -e "1) GOST\n2) HAProxy"; read -p "Choice: " t
            if [ "$t" == "1" ]; then
                # بخش GOST قبلی شما
                echo "GOST management here..."
            else
                # بخش HAProxy قبلی شما
                echo "HAProxy management here..."
            fi
            read -p "Press Enter..."
            ;;
        3) setup_telegram ;;
        4) setup_auto_healer ;;
        5) source $TELEGRAM_CONF 2>/dev/null; curl -sk -X POST "$TG_URL/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=📊 Manual Report for $(hostname)"; read -p "Press Enter..." ;;
        6) clear; wg show; systemctl status tunnel --no-pager; read -p "Press Enter..." ;;
        7) systemctl stop tunnel 2>/dev/null; systemctl disable tunnel 2>/dev/null; rm -rf /etc/wireguard /opt/udp2raw /etc/systemd/system/tunnel.service $TELEGRAM_CONF; echo "Uninstalled."; read -p "Press Enter..." ;;
        8) exit 0 ;;
    esac
done
