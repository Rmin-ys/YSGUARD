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

# --- 2. Port Forwarders (GOST & HAProxy) ---

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
               read -p "Enter Port(s) (e.g. 80,443): " PORTS; IFS=',' read -ra ADDR <<< "$PORTS"
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
               done; echo -e "${GREEN}✔ Ports forwarded via GOST.${NC}" ;;
            3) read -p "Port: " R_PORT; systemctl stop gost-$R_PORT 2>/dev/null; systemctl disable gost-$R_PORT 2>/dev/null; rm -f /etc/systemd/system/gost-$R_PORT.service; systemctl daemon-reload; echo -e "${GREEN}✔ Port $R_PORT removed.${NC}" ;;
            4) break ;;
        esac
    done
}

manage_haproxy() {
    while true; do
        echo -e "\n${CYAN}>>> HAProxy Port Forwarder <<<${NC}"
        echo "1) Install HAProxy"
        echo "2) Add New Port(s)"
        echo "3) Remove Specific Port"
        echo "4) Back"
        read -p "Select [1-4]: " h_opt
        case $h_opt in
            1) apt update && apt install haproxy -y && systemctl enable haproxy; echo -e "${GREEN}✔ HAProxy installed.${NC}" ;;
            2) read -p "Enter Port(s): " PORTS; IFS=',' read -ra ADDR <<< "$PORTS"
               for port in "${ADDR[@]}"; do
                   if ! grep -q "listen forward-$port" $HAPROXY_CONF; then
                       echo -e "listen forward-$port\n    bind :$port\n    mode tcp\n    server srv1 10.0.0.1:$port" >> $HAPROXY_CONF
                   fi
               done
               systemctl restart haproxy && echo -e "${GREEN}✔ Ports added to HAProxy.${NC}" ;;
            3) read -p "Port to remove: " R_PORT; sed -i "/listen forward-$R_PORT/,+3d" $HAPROXY_CONF; systemctl restart haproxy; echo -e "${GREEN}✔ Port removed.${NC}" ;;
            4) break ;;
        esac
    done
}

setup_port_forward() {
    echo -e "\n${CYAN}--- Port Forwarding Menu ---${NC}"
    echo "1) GOST (TCP/UDP Support)"
    echo "2) HAProxy (TCP Only)"
    echo "3) Global Forwarding Reset (Clean All)"
    echo "4) Back"
    read -p "Select: " tool
    case $tool in
        1) manage_gost ;;
        2) manage_haproxy ;;
        3) systemctl stop gost-* 2>/dev/null; rm -f /etc/systemd/system/gost-*.service; 
           [ -f $HAPROXY_CONF ] && echo "" > $HAPROXY_CONF && systemctl restart haproxy; 
           systemctl daemon-reload; echo -e "${RED}✔ All forwards cleared.${NC}" ;;
        4) return ;;
    esac
}

# --- 3. Telegram & Healer ---

setup_telegram() {
    echo -e "\n${CYAN}--- Telegram Bot Configuration ---${NC}"
    read -p "Enter Bot Token: " BTN; BTN=$(echo $BTN | sed 's/\$//g')
    read -p "Enter Chat ID: " CID; CID=$(echo $CID | sed 's/\$//g')
    echo "TOKEN=$BTN" > $TELEGRAM_CONF; echo "CHATID=$CID" >> $TELEGRAM_CONF
    curl -s -X POST "https://api.telegram.org/bot$BTN/sendMessage" -d "chat_id=$CID" -d "text=✅ MASTER TUNNEL PRO Connected!" > /dev/null
    echo -e "${GREEN}✔ Linked & Test message sent.${NC}"
    read -p "Press Enter..."
}

# --- بخش ۴: نسخه نهایی و ضد خطا ---
# --- بخش ۴: نسخه نهایی با گزارش روزانه و بدون فایل لاگ ---
setup_auto_healer() {
    # ایجاد فایل ذخیره تعداد ریست‌ها
    echo "0" > /etc/tunnel_reset_count
    chmod 666 /etc/tunnel_reset_count

    cat <<'EOF' > $HEALER_SCRIPT
#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[ -f /etc/tunnel_telegram.conf ] && source /etc/tunnel_telegram.conf

TARGET="10.0.0.1"
if grep -q "10.0.0.1" /etc/wireguard/wg0.conf; then TARGET="10.0.0.2"; fi

# تابع بررسی هوشمند
check_connection() {
    if ! ip link show wg0 > /dev/null 2>&1; then return 1; fi
    for i in {1..3}; do
        if ping -c 1 -W 3 $TARGET > /dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

# عملیات احیا
if ! check_connection; then
    systemctl stop tunnel > /dev/null 2>&1
    wg-quick down wg0 > /dev/null 2>&1
    ip link delete wg0 > /dev/null 2>&1
    systemctl start tunnel > /dev/null 2>&1
    sleep 5
    wg-quick up wg0 > /dev/null 2>&1
    
    # افزایش آمار ریست‌های روزانه
    COUNT=$(cat /etc/tunnel_reset_count)
    echo $((COUNT + 1)) > /etc/tunnel_reset_count

    if [ -n "$TOKEN" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=🚨 *Auto-Heal Done!*%0A🌐 Host: $(hostname)%0A🔄 Status: Tunnel Recovered successfully." -d "parse_mode=Markdown" > /dev/null
    fi
fi

# ارسال گزارش روزانه در ساعت ۰۰:۰۰
if [ "$(date +%H:%M)" == "00:00" ]; then
    FINAL_COUNT=$(cat /etc/tunnel_reset_count)
    if [ -n "$TOKEN" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=📊 *Daily Tunnel Report*%0A📅 Date: $(date +%Y-%m-%d)%0A🔄 Total Auto-Heals today: $FINAL_COUNT" -d "parse_mode=Markdown" > /dev/null
    fi
    echo "0" > /etc/tunnel_reset_count
fi
EOF
    chmod +x $HEALER_SCRIPT
    (crontab -l 2>/dev/null | grep -v "tunnel_healer.sh"; echo "* * * * * $HEALER_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Ultimate Smart Healer with Daily Report installed.${NC}"
}

# --- بخش ۵: اصلاح شده ---
setup_daily_report() {
    apt install bc -y >/dev/null 2>&1
    cat <<'EOF' > $REPORT_SCRIPT
#!/bin/bash
[ -f /etc/tunnel_telegram.conf ] && source /etc/tunnel_telegram.conf || exit 1
# محاسبه ترافیک به گیگابایت
RX_BYTES=$(wg show wg0 transfer | awk '{print $2}' | sed 's/[^0-9.]//g')
TX_BYTES=$(wg show wg0 transfer | awk '{print $3}' | sed 's/[^0-9.]//g')
TOTAL_GB=$(echo "scale=2; ($RX_BYTES+$TX_BYTES)/1024/1024/1024" | bc)

if [ -n "$TOKEN" ]; then
    curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=📊 Daily Traffic Report%0AHost: $(hostname)%0AUsage: $TOTAL_GB GB" > /dev/null
fi
EOF
    chmod +x $REPORT_SCRIPT
    # تنظیم برای ساعت ۲۳:۵۹ هر شب
    (crontab -l 2>/dev/null | grep -v "tunnel_report.sh"; echo "59 23 * * * $REPORT_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Daily Traffic Report (v7.9) enabled.${NC}"
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
    echo -e "${WHITE}              [ MASTER TUNNEL PRO v1.01 ]${NC}"
    echo -e "${CYAN}========================================================${NC}"
    systemctl is-active --quiet tunnel && echo -e "Tunnel (udp2raw): ${GREEN}RUNNING${NC}" || echo -e "Tunnel: ${RED}STOPPED${NC}"
    wg show wg0 2>/dev/null | grep -q "interface" && echo -e "WireGuard (wg0):  ${GREEN}ACTIVE${NC}" || echo -e "WireGuard: ${RED}INACTIVE${NC}"
    
    G_COUNT=$(ls /etc/systemd/system/gost-*.service 2>/dev/null | wc -l)
    H_COUNT=$(grep -c "listen forward-" $HAPROXY_CONF 2>/dev/null || echo 0)
    echo -e "Active Forwards:  ${YELLOW}GOST ($G_COUNT), HAProxy ($H_COUNT)${NC}"
    
    echo -e "\nTraffic Data:"
    wg show wg0 transfer 2>/dev/null || echo "No data available."
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
    echo -e "${WHITE}              [ MASTER TUNNEL PRO v1.01 ]${NC}"
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
       while true; do
           read -p "Enter Tunnel Password: " T_PASS
           [ -n "$T_PASS" ] && break || echo -e "${RED}Error: Cannot be empty!${NC}"
       done
       read -p "WireGuard MTU [Default 1280]: " T_MTU; T_MTU=${T_MTU:-1280}
       echo -e "1) Foreign\n2) Iran"; read -p "Role: " role
       
       [ ! -d /opt/udp2raw ] && mkdir -p /opt/udp2raw && curl -L https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -o /tmp/u.tar.gz && tar -xzvf /tmp/u.tar.gz -C /tmp/ && mv /tmp/udp2raw_amd64 /opt/udp2raw/udp2raw && chmod +x /opt/udp2raw/udp2raw
       
       echo -e "\n${YELLOW}--- YOUR PUBLIC KEY: $MY_PUB ---${NC}\n"

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
       systemctl daemon-reload && systemctl enable --now tunnel; echo -e "${GREEN}✔ Done.${NC}"; read -p "Press Enter..." ;;
    2) setup_port_forward ;;
    3) setup_telegram ;;
    4) setup_auto_healer ;;
    5) setup_daily_report ;;
    6) show_status ;;
    7) 
       systemctl stop tunnel gost-* haproxy 2>/dev/null; systemctl disable tunnel gost-* 2>/dev/null; wg-quick down wg0 2>/dev/null
       rm -rf /etc/wireguard /opt/udp2raw /etc/systemd/system/tunnel.service /etc/systemd/system/gost-*.service
       rm -f /etc/sysctl.d/99-tunnel.conf $REPORT_SCRIPT $HEALER_SCRIPT $TELEGRAM_CONF
       crontab -l 2>/dev/null | grep -vE "tunnel_healer.sh|tunnel_report.sh" | crontab -
       systemctl daemon-reload; echo -e "${RED}✔ UNINSTALLED.${NC}"; read -p "Press Enter..." ;;
    8) exit 0 ;;
esac
done
