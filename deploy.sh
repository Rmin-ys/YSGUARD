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

# --- 2. Port Forwarder (Hierarchical Menu from v6.7) ---

manage_gost() {
    while true; do
        echo -e "\n${CYAN}>>> GOST Port Forwarder <<<${NC}"
        echo "1) Install/Update GOST"
        echo "2) Add New Port(s) (e.g. 80,443)"
        echo "3) Remove Specific Port"
        echo "4) Show Active GOST Ports"
        echo "5) Back to Port Menu"
        read -p "Select [1-5]: " g_opt

        case $g_opt in
            1) echo -e "${YELLOW}[*] Downloading GOST...${NC}"
               curl -L https://github.com/ginuerzh/gost/releases/download/v2.11.1/gost-linux-amd64-2.11.1.gz | gunzip > $GOST_BIN
               chmod +x $GOST_BIN && echo -e "${GREEN}✔ GOST installed.${NC}" ;;
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
                   echo -e "${GREEN}✔ Port $port forwarded.${NC}"
               done ;;
            3) read -p "Enter port to REMOVE: " R_PORT; systemctl stop gost-$R_PORT 2>/dev/null; systemctl disable gost-$R_PORT 2>/dev/null; rm -f /etc/systemd/system/gost-$R_PORT.service; systemctl daemon-reload; echo -e "${GREEN}✔ Port $R_PORT removed.${NC}" ;;
            4) echo -e "${YELLOW}Active GOST Ports:${NC}"; ls /etc/systemd/system/gost-*.service 2>/dev/null | cut -d'-' -f2 | cut -d'.' -f1 || echo "None" ;;
            5) break ;;
        esac
    done
}

manage_haproxy() {
    while true; do
        echo -e "\n${CYAN}>>> HAProxy Port Forwarder <<<${NC}"
        echo "1) Install HAProxy"
        echo "2) Add New Port(s) (e.g. 80,443)"
        echo "3) Remove Specific Port"
        echo "4) Show Active HAProxy Ports"
        echo "5) Back to Port Menu"
        read -p "Select [1-5]: " h_opt

        case $h_opt in
            1) echo -e "${YELLOW}[*] Installing HAProxy...${NC}"; apt update && apt install haproxy -y; systemctl enable haproxy; echo -e "${GREEN}✔ HAProxy installed.${NC}" ;;
            2) if ! command -v haproxy &> /dev/null; then echo -e "${RED}✘ HAProxy not installed!${NC}"; continue; fi
               read -p "Enter Port(s): " PORTS; IFS=',' read -ra ADDR <<< "$PORTS"
               for port in "${ADDR[@]}"; do
                   if ! grep -q "listen forward-$port" $HAPROXY_CONF; then
                       echo -e "listen forward-$port\n    bind :$port\n    mode tcp\n    server srv1 10.0.0.1:$port" >> $HAPROXY_CONF
                       echo -e "${GREEN}✔ Port $port added.${NC}"
                   fi
               done
               systemctl restart haproxy ;;
            3) read -p "Enter port: " R_PORT; sed -i "/listen forward-$R_PORT/,+3d" $HAPROXY_CONF; systemctl restart haproxy; echo -e "${GREEN}✔ Port $R_PORT removed.${NC}" ;;
            4) echo -e "${YELLOW}Active HAProxy Ports:${NC}"; grep "listen forward-" $HAPROXY_CONF | cut -d'-' -f2 || echo "None" ;;
            5) break ;;
        esac
    done
}

setup_port_forward() {
    echo -e "\n${CYAN}--- Port Forwarding ---${NC}"
    echo "1) GOST (TCP/UDP)"
    echo "2) HAProxy (TCP)"
    echo "3) Global Reset"
    echo "4) Back"
    read -p "Select: " tool
    case $tool in
        1) manage_gost ;;
        2) manage_haproxy ;;
        3) systemctl stop gost-* 2>/dev/null; rm -f /etc/systemd/system/gost-*.service; echo "" > $HAPROXY_CONF; systemctl restart haproxy; systemctl daemon-reload; echo -e "${RED}✔ All Cleared.${NC}" ;;
    esac
}

# --- 3. Telegram, Healer & NEW: Daily Report ---

setup_telegram() {
    echo -e "\n${CYAN}--- Telegram Bot ---${NC}"
    read -p "Enter Bot Token: " BTN; read -p "Enter Chat ID: " CID
    echo "TOKEN=$BTN" > $TELEGRAM_CONF; echo "CHATID=$CID" >> $TELEGRAM_CONF
    echo -e "${GREEN}✔ Telegram linked!${NC}"
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
    echo -e "${YELLOW}[*] Setting up Daily Traffic Report...${NC}"
    apt install bc -y >/dev/null 2>&1
    cat <<'EOF' > $REPORT_SCRIPT
#!/bin/bash
if [ -f /etc/tunnel_telegram.conf ]; then source /etc/tunnel_telegram.conf; else exit 1; fi
RX_BYTES=$(wg show wg0 transfer | awk '{print $2}' | sed 's/[^0-9.]//g')
TX_BYTES=$(wg show wg0 transfer | awk '{print $3}' | sed 's/[^0-9.]//g')
TOTAL_GB=$(echo "scale=2; ($RX_BYTES+$TX_BYTES)/1024/1024/1024" | bc)
MSG="📊 *Daily Report* ($(hostname))%0A💎 *Total Usage: $TOTAL_GB GB*"
curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "parse_mode=Markdown" -d "text=$MSG" > /dev/null
EOF
    chmod +x $REPORT_SCRIPT
    (crontab -l 2>/dev/null | grep -v "tunnel_report.sh"; echo "59 23 * * * $REPORT_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Daily Report enabled (Every night at 23:59).${NC}"
}

# --- 4. Status (Exactly from v6.7) ---

show_status() {
    clear
    echo -e "${CYAN}========================================================"
    echo -e "${CYAN}██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo -e "╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo -e " ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo -e "  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo -e "   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo -e "   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${WHITE}              [ MASTER TUNNEL PRO v1.00 ]${NC}"
    echo -e "${CYAN}========================================================${NC}"
    
    systemctl is-active --quiet tunnel && echo -e "Tunnel (UDP2RAW): ${GREEN}RUNNING${NC}" || echo -e "Tunnel: ${RED}STOPPED${NC}"
    wg show wg0 2>/dev/null | grep -q "interface" && echo -e "WireGuard (wg0):  ${GREEN}ACTIVE${NC}" || echo -e "WireGuard:  ${RED}INACTIVE${NC}"
    GOST_COUNT=$(ls /etc/systemd/system/gost-*.service 2>/dev/null | wc -l)
    HAP_COUNT=$(grep -c "listen forward-" $HAPROXY_CONF 2>/dev/null || echo 0)
    echo -e "GOST Forwards:    ${YELLOW}$GOST_COUNT Active${NC}"
    echo -e "HAProxy Forwards: ${YELLOW}$HAP_COUNT Active${NC}"
    BBR_STATE=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    echo -e "TCP Congestion:   ${GREEN}$BBR_STATE${NC}"
    [ -f $TELEGRAM_CONF ] && echo -e "Telegram Bot:     ${GREEN}LINKED${NC}" || echo -e "Telegram Bot:     ${RED}NOT SET${NC}"
    echo -e "${CYAN}--------------------------------------------------------${NC}"
    echo -e "${WHITE}LIVE TRAFFIC (WireGuard Interface):${NC}"
    wg show wg0 transfer 2>/dev/null || echo "No data yet."
    echo -e "${CYAN}========================================================${NC}"
    read -p "Press Enter to return..."
}

# --- Main Menu ---

while true; do
clear
echo -e "${CYAN}========================================================"
echo -e "           MASTER TUNNEL PRO - VERSION 6.9"
echo -e "========================================================${NC}"
echo "1) Install/Update Tunnel (Core)"
echo "2) Port Forwarder (GOST / HAProxy)"
echo "3) Telegram Bot Settings"
echo "4) Anti-Lag Auto-Healer"
echo "5) Daily Traffic Report"
echo "6) Show Full System Status"
echo "7) Full Uninstall"
echo "8) Exit"
echo -ne "${YELLOW}Select an option: ${NC}"
read opt

case $opt in
    1) optimize_system; apt update && apt install -y wireguard iptables curl tar vnstat bc > /dev/null 2>&1
       mkdir -p /etc/wireguard; [ ! -f /etc/wireguard/private.key ] && wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
       MY_PUB=$(cat /etc/wireguard/public.key); MY_PRIV=$(cat /etc/wireguard/private.key); echo -e "\n${GREEN}PubKey: ${YELLOW}$MY_PUB${NC}"
       read -p "Port [443]: " T_PORT; T_PORT=${T_PORT:-443}
       echo -e "1) Foreign\n2) Iran"; read -p "Role: " role
       [ ! -d /opt/udp2raw ] && mkdir -p /opt/udp2raw && curl -L https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -o /tmp/u.tar.gz && tar -xzvf /tmp/u.tar.gz -C /tmp/ && mv /tmp/udp2raw_amd64 /opt/udp2raw/udp2raw && chmod +x /opt/udp2raw/udp2raw
       if [ "$role" == "1" ]; then read -p "Iran PubKey: " PEER_PUB
         echo -e "[Interface]\nPrivateKey = $MY_PRIV\nAddress = 10.0.0.1/24\nListenPort = 51820\nMTU = 1280\n[Peer]\nPublicKey = $PEER_PUB\nAllowedIPs = 10.0.0.2/32" > /etc/wireguard/wg0.conf
         EXEC="/opt/udp2raw/udp2raw -s -l0.0.0.0:$T_PORT -r 127.0.0.1:51820 -k '505752' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
         IPT="-I INPUT -p tcp --dport $T_PORT -j DROP"
       else read -p "Foreign IP: " F_IP; read -p "Foreign PubKey: " PEER_PUB
         echo -e "[Interface]\nPrivateKey = $MY_PRIV\nAddress = 10.0.0.2/24\nMTU = 1280\n[Peer]\nPublicKey = $PEER_PUB\nEndpoint = 127.0.0.1:3333\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25" > /etc/wireguard/wg0.conf
         EXEC="/opt/udp2raw/udp2raw -c -l127.0.0.1:3333 -r $F_IP:$T_PORT -k '505752' --raw-mode faketcp --cipher-mode xor --auth-mode md5 --seq-mode 3"
         IPT="-I INPUT -p tcp --sport $T_PORT -j DROP"; apply_qos
       fi
       cat <<EOF > /etc/systemd/system/tunnel.service
[Unit]
Description=Tunnel Service
[Service]
ExecStartPre=-/sbin/iptables $IPT
ExecStart=$EXEC
ExecStopPost=-/sbin/iptables -D ${IPT/-I/-D}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
       systemctl daemon-reload && systemctl enable --now tunnel; wg-quick down wg0 2>/dev/null; wg-quick up wg0; echo -e "${GREEN}✔ Done.${NC}"; read -p "Press Enter..." ;;
    2) setup_port_forward ;;
    3) setup_telegram ;;
    4) setup_auto_healer ;;
    5) setup_daily_report ;;
    6) show_status ;;
    7) systemctl stop tunnel gost-* haproxy 2>/dev/null; rm -rf /etc/wireguard /opt/udp2raw /etc/systemd/system/tunnel.service /etc/systemd/system/gost-*.service; echo -e "${RED}Uninstalled.${NC}"; read -p "Press Enter..." ;;
    8) exit 0 ;;
esac
done
