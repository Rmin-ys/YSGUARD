#!/bin/bash

# --- Colors & Essentials ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
WHITE='\033[1;37m'

TELEGRAM_CONF="/etc/tunnel_telegram.conf"
HEALER_SCRIPT="/usr/local/bin/tunnel_healer.sh"
REPORT_SCRIPT="/usr/local/bin/tunnel_report.sh"
GOST_BIN="/usr/local/bin/gost"
HAPROXY_CONF="/etc/haproxy/haproxy.cfg"

# --- 1. Optimization Functions ---

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

# --- 2. Port Forwarder ---

manage_gost() {
    while true; do
        echo -e "\n${CYAN}>>> GOST Port Forwarder <<<${NC}"
        echo "1) Install/Update GOST"
        echo "2) Add New Port(s)"
        echo "3) Remove Specific Port"
        echo "4) Back"
        read -p "Select [1-4]: " g_opt
        case $g_opt in
            1) curl -L https://github.com/ginuerzh/gost/releases/download/v2.11.1/gost-linux-amd64-2.11.1.gz | gunzip > $GOST_BIN && chmod +x $GOST_BIN && echo -e "${GREEN}✔ GOST installed.${NC}" ;;
            2) [ ! -f $GOST_BIN ] && echo -e "${RED}✘ Install GOST first!${NC}" && continue
               read -p "Enter Port(s): " PORTS; IFS=',' read -ra ADDR <<< "$PORTS"
               for port in "${ADDR[@]}"; do
                   cat <<EOF > /etc/systemd/system/gost-$port.service
[Unit]
Description=GOST Forward Port $port
After=network.target tunnel.service
[Service]
ExecStart=$GOST_BIN -L tcp://:$port/10.0.0.1:$port -L udp://:$port/10.0.0.1:$port
Restart=always
[Install]
WantedBy=multi-user.target
EOF
                   systemctl daemon-reload && systemctl enable --now gost-$port
               done; echo -e "${GREEN}✔ Ports forwarded.${NC}" ;;
            3) read -p "Port: " R_PORT; systemctl stop gost-$R_PORT 2>/dev/null; systemctl disable gost-$R_PORT 2>/dev/null; rm -f /etc/systemd/system/gost-$R_PORT.service; systemctl daemon-reload; echo -e "${GREEN}✔ Removed.${NC}" ;;
            4) break ;;
        esac
    done
}

# --- 3. Telegram, Healer & Daily Report ---

setup_telegram() {
    echo -e "\n${CYAN}--- Telegram Bot Configuration ---${NC}"
    read -p "Enter Bot Token: " BTN; BTN=$(echo $BTN | sed 's/\$//g')
    read -p "Enter Chat ID: " CID; CID=$(echo $CID | sed 's/\$//g')
    echo "TOKEN=$BTN" > $TELEGRAM_CONF; echo "CHATID=$CID" >> $TELEGRAM_CONF
    echo -e "${YELLOW}[*] Sending test message...${NC}"
    curl -s -X POST "https://api.telegram.org/bot$BTN/sendMessage" -d "chat_id=$CID" -d "text=✅ MASTER TUNNEL PRO Connected!%0AHost: $(hostname)" > /dev/null
    echo -e "${GREEN}✔ Linked & Test message sent.${NC}"
    read -p "Press Enter..."
}

setup_auto_healer() {
    cat <<'EOF' > $HEALER_SCRIPT
#!/bin/bash
TARGET="10.0.0.1"; [ -f /etc/wireguard/wg0.conf ] && grep -q "10.0.0.1" /etc/wireguard/wg0.conf && TARGET="10.0.0.2"
PING_RESULT=$(ping -c 4 $TARGET | tail -1 | awk '{print $4}' | cut -d '/' -f 2 | cut -d '.' -f 1)
if [ -z "$PING_RESULT" ] || [ "$PING_RESULT" -gt 300 ]; then
    systemctl restart tunnel; wg-quick down wg0; wg-quick up wg0
    [ -f /etc/tunnel_telegram.conf ] && source /etc/tunnel_telegram.conf && curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=🚨 Tunnel Healed on $(hostname)" > /dev/null
fi
EOF
    chmod +x $HEALER_SCRIPT; (crontab -l 2>/dev/null | grep -v "tunnel_healer.sh"; echo "* * * * * $HEALER_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Healer active.${NC}"
}

setup_daily_report() {
    apt install bc -y >/dev/null 2>&1
    cat <<'EOF' > $REPORT_SCRIPT
#!/bin/bash
if [ -f /etc/tunnel_telegram.conf ]; then source /etc/tunnel_telegram.conf; else exit 1; fi
RX_BYTES=$(wg show wg0 transfer | awk '{print $2}' | sed 's/[^0-9.]//g'); TX_BYTES=$(wg show wg0 transfer | awk '{print $3}' | sed 's/[^0-9.]//g')
TOTAL_GB=$(echo "scale=2; ($RX_BYTES+$TX_BYTES)/1024/1024/1024" | bc)
MSG="📊 Daily Report ($(hostname)): $TOTAL_GB GB"
curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=$MSG" > /dev/null
EOF
    chmod +x $REPORT_SCRIPT; (crontab -l 2>/dev/null | grep -v "tunnel_report.sh"; echo "59 23 * * * $REPORT_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Daily Report enabled.${NC}"
}

# --- 4. Status ---

show_status() {
    clear
    echo -e "${CYAN}========================================================"
    echo -e "${CYAN}██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo -e "╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo -e " ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo -e "  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo -e "   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo -e "   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${WHITE}              [ MASTER TUNNEL PRO v1.05 ]${NC}"
    echo -e "${CYAN}========================================================${NC}"
    systemctl is-active --quiet tunnel && echo -e "Tunnel: ${GREEN}RUNNING${NC}" || echo -e "Tunnel: ${RED}STOPPED${NC}"
    wg show wg0 2>/dev/null | grep -q "interface" && echo -e "WireGuard: ${GREEN}ACTIVE${NC}" || echo -e "WireGuard: ${RED}INACTIVE${NC}"
    echo -e "Traffic:"
    wg show wg0 transfer 2>/dev/null || echo "No data."
    echo -e "${CYAN}========================================================${NC}"
    read -p "Press Enter..."
}

# --- Main Menu ---

while true; do
clear
    echo -e "${CYAN}========================================================"
    echo -e "${CYAN}██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo -e "╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo -e " ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo -e "  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo -e "   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo -e "   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${WHITE}              [ MASTER TUNNEL PRO v1.05 ]${NC}"
    echo -e "${CYAN}========================================================${NC}"
echo "1) Install/Update Tunnel (Core)"
echo "2) Port Forwarder (GOST / HAProxy)"
echo "3) Telegram Bot Settings"
echo "4) Anti-Lag Auto-Healer"
echo "5) Daily Traffic Report"
echo "6) Show Full System Status"
echo "7) Full Uninstall"
echo "8) Exit"
read -p "Select: " opt

case $opt in
    1) optimize_system; apt update && apt install -y wireguard iptables curl tar bc > /dev/null 2>&1
       mkdir -p /etc/wireguard; [ ! -f /etc/wireguard/private.key ] && wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
       MY_PUB=$(cat /etc/wireguard/public.key); MY_PRIV=$(cat /etc/wireguard/private.key)
       
       read -p "Tunnel Port [Default 443]: " T_PORT; T_PORT=${T_PORT:-443}
       
       # بخش دریافت رمز بدون مقدار پیش‌فرض لو رفته
       while true; do
           read -p "Enter Tunnel Password: " T_PASS
           if [ -z "$T_PASS" ]; then
               echo -e "${RED}Error: Password cannot be empty!${NC}"
           else
               break
           fi
       done

       read -p "WireGuard MTU [Default 1280]: " T_MTU; T_MTU=${T_MTU:-1280}
       
       echo -e "1) Foreign\n2) Iran"; read -p "Role: " role
       
       [ ! -d /opt/udp2raw ] && mkdir -p /opt/udp2raw && curl -L https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -o /tmp/u.tar.gz && tar -xzvf /tmp/u.tar.gz -C /tmp/ && mv /tmp/udp2raw_amd64 /opt/udp2raw/udp2raw && chmod +x /opt/udp2raw/udp2raw
       
       echo -e "\n${YELLOW}-----------------------------------------${NC}"
       echo -e "${GREEN}YOUR PUBLIC KEY:${NC} ${WHITE}$MY_PUB${NC}"
       echo -e "${YELLOW}-----------------------------------------${NC}\n"

       if [ "$role" == "1" ]; then read -p "Iran PubKey: " PEER_PUB
         echo -e "[Interface]\nPrivateKey = $MY_PRIV\nAddress = 10.0.0.1/24\nListenPort = 51820\nMTU = $T_MTU\n[Peer]\nPublicKey = $PEER_PUB\nAllowedIPs = 10.0.0.2/32" > /etc/wireguard/wg0.conf
         EXEC="/opt/udp2raw/udp2raw -s -l0.0.0.0:$T_PORT -r 127.0.0.1:51820 -k '$T_PASS' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
         IPT="-I INPUT -p tcp --dport $T_PORT -j DROP"
       else read -p "Foreign IP: " F_IP; read -p "Foreign PubKey: " PEER_PUB
         echo -e "[Interface]\nPrivateKey = $MY_PRIV\nAddress = 10.0.0.2/24\nMTU = $T_MTU\n[Peer]\nPublicKey = $PEER_PUB\nEndpoint = 127.0.0.1:3333\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25" > /etc/wireguard/wg0.conf
         EXEC="/opt/udp2raw/udp2raw -c -l127.0.0.1:3333 -r $F_IP:$T_PORT -k '$T_PASS' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
         IPT="-I INPUT -p tcp --sport $T_PORT -j DROP"; apply_qos
       fi
       cat <<EOF > /etc/systemd/system/tunnel.service
[Unit]
Description=Tunnel Service
After=network.target
[Service]
ExecStartPre=-/sbin/iptables $IPT
ExecStart=$EXEC
ExecStartPost=/usr/bin/wg-quick up wg0
ExecStop=/usr/bin/wg-quick down wg0
ExecStopPost=-/sbin/iptables -D ${IPT/-I/-D}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
       systemctl daemon-reload && systemctl enable --now tunnel; echo -e "${GREEN}✔ Installation Finished.${NC}"; read -p "Press Enter..." ;;
    2) echo -e "1) GOST\n2) HAProxy"; read -p "Select: " p_opt; [ "$p_opt" == "1" ] && manage_gost ;;
    3) setup_telegram ;;
    4) setup_auto_healer ;;
    5) setup_daily_report ;;
    6) show_status ;;
    7) 
       echo -e "\n${YELLOW}[!] Starting Full Uninstall...${NC}"
       systemctl stop tunnel gost-* haproxy 2>/dev/null && echo -e "${GREEN}✔ Services stopped.${NC}"
       systemctl disable tunnel gost-* 2>/dev/null && echo -e "${GREEN}✔ Autostart disabled.${NC}"
       wg-quick down wg0 2>/dev/null && echo -e "${GREEN}✔ Network closed.${NC}"
       rm -rf /etc/wireguard /opt/udp2raw /etc/systemd/system/tunnel.service /etc/systemd/system/gost-*.service
       rm -f /etc/sysctl.d/99-tunnel.conf $REPORT_SCRIPT $HEALER_SCRIPT $TELEGRAM_CONF
       crontab -l 2>/dev/null | grep -vE "tunnel_healer.sh|tunnel_report.sh" | crontab -
       systemctl daemon-reload
       echo -e "${RED}✔ UNINSTALL COMPLETED SUCCESSFULLY.${NC}"; read -p "Press Enter..." ;;
    8) exit 0 ;;
esac
done
