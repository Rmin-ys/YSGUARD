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
    clear
    echo -e "\n${CYAN}--- Telegram Bot Configuration ---${NC}"
    read -p "Enter Bot Token: " BTN; BTN=$(echo $BTN | sed 's/\$//g')
    read -p "Enter Chat ID: " CID; CID=$(echo $CID | sed 's/\$//g')
    
    echo -e "\n${YELLOW}Where is this server located?${NC}"
    echo "1) Outside Iran (Direct Connection)"
    echo "2) Inside Iran (Needs Cloudflare Worker Proxy)"
    read -p "Select [1-2]: " loc_opt

    if [ "$loc_opt" == "2" ]; then
        echo -e "\n${WHITE}Enter Worker URL (e.g., bot.venuseco.ir or bot.ir:8080):${NC}"
        read -p "URL: " W_URL
        W_URL=$(echo $W_URL | sed 's|https://||g;s|http://||g;s|/||g')
        
        echo -e "${YELLOW}Use Secure HTTPS? (y/n) [Recommended 'n' for .ir]:${NC}"
        read -p "Selection: " ssl_choice
        [[ "$ssl_choice" == "y" || "$ssl_choice" == "Y" ]] && TG_BASE="https://$W_URL" || TG_BASE="http://$W_URL"
    else
        TG_BASE="https://api.telegram.org"
    fi

    echo "TOKEN=$BTN" > $TELEGRAM_CONF
    echo "CHATID=$CID" >> $TELEGRAM_CONF
    echo "TG_URL=$TG_BASE" >> $TELEGRAM_CONF

    echo -e "\n${YELLOW}[*] Sending test message to $TG_BASE ...${NC}"
    RESULT=$(curl -sk --connect-timeout 10 -X POST "$TG_BASE/bot$BTN/sendMessage" -d "chat_id=$CID" -d "text=✅ MASTER TUNNEL PRO Connected via $TG_BASE")

    [[ $RESULT == *"ok\":true"* ]] && echo -e "${GREEN}✔ Linked!${NC}" || echo -e "${RED}❌ Failed: $RESULT${NC}"
    read -p "Press Enter..."
}



send_daily_report() {
    while true; do
        clear
        echo -e "${CYAN}--- Daily Traffic Report Settings ---${NC}"
        echo "1) Send Report NOW (Instant)"
        echo "2) Set/Change Auto-Report Time (Default 00:00)"
        echo "3) Disable Daily Report"
        echo "4) Back"
        read -p "Select [1-4]: " r_opt

        case $r_opt in
            1)
                echo -e "${YELLOW}[*] Collecting data and sending...${NC}"
                [ -f $TELEGRAM_CONF ] && source $TELEGRAM_CONF
                if [ -z "$TOKEN" ]; then
                    echo -e "${RED}❌ Telegram not configured!${NC}"
                else
                    RC=$(cat /etc/tunnel_reset_count 2>/dev/null || echo 0)
                    S=$(wg show wg0 transfer 2>/dev/null)
                    CD=$(echo $S | awk '{print $2}' | sed 's/[^0-9]//g'); CU=$(echo $S | awk '{print $5}' | sed 's/[^0-9]//g')
                    TD=$(( $(cat /etc/total_down 2>/dev/null || echo 0) + ${CD:-0} )); TU=$(( $(cat /etc/total_up 2>/dev/null || echo 0) + ${CU:-0} ))
                    MSG="📊 *Manual Traffic Report*%0A🖥 *Host:* $(hostname)%0A🔄 *Resets:* $RC%0A📥 *Total Down:* $((TD/1048576)) MB%0A📤 *Total Up:* $((TU/1048576)) MB"
                    curl -sk -X POST "$TG_URL/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=$MSG" -d "parse_mode=Markdown" >/dev/null 2>&1
                    echo -e "${GREEN}✔ Report sent!${NC}"
                fi
                sleep 2 ;;
            2)
                read -p "Enter Time (HH:MM): " R_TIME
                if [[ $R_TIME =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; then
                    sed -i "s/== \"[0-9]\{2\}:[0-9]\{2\}\"/== \"$R_TIME\"/g" $HEALER_SCRIPT
                    echo -e "${GREEN}✔ Time updated to $R_TIME.${NC}"
                else echo -e "${RED}❌ Invalid format!${NC}"; fi
                sleep 2 ;;
            3)
                sed -i "s/== \"[0-9]\{2\}:[0-9]\{2\}\"/== \"OFF\"/g" $HEALER_SCRIPT
                echo -e "${YELLOW}✔ Disabled.${NC}"
                sleep 2 ;;
            4) break ;;
        esac
    done
}

setup_auto_healer() {
    touch /etc/tunnel_reset_count /etc/total_down /etc/total_up
    chmod 666 /etc/tunnel_reset_count /etc/total_down /etc/total_up

    cat <<'EOF' > $HEALER_SCRIPT
#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[ -f /etc/tunnel_telegram.conf ] && source /etc/tunnel_telegram.conf
TARGET="10.0.0.1"; grep -q "10.0.0.1" /etc/wireguard/wg0.conf && TARGET="10.0.0.2"

check_connection() {
    # لایه ۱: بررسی وجود اینترفیس
    if ! ip link show wg0 > /dev/null 2>&1; then return 1; fi

    # لایه ۲ و ۳: پینگ ۴ تایی از داخل تانل و استخراج میانگین
    PING_RES=$(ping -I wg0 -c 4 $TARGET 2>/dev/null | tail -1 | awk -F'/' '{print $5}' | cut -d'.' -f1)

    # حساسیت روی ۳۰۰ میلی‌ثانیه (مناسب برای تانل‌های ایران)
    if [ -z "$PING_RES" ] || [ "$PING_RES" -lt 1 ] || [ "$PING_RES" -gt 300 ]; then
        return 1
    fi
    return 0
}

if ! check_connection; then
    STATS=$(wg show wg0 transfer 2>/dev/null)
    D=$(echo $STATS | awk '{print $2}' | sed 's/[^0-9]//g'); U=$(echo $STATS | awk '{print $5}' | sed 's/[^0-9]//g')
    [ -n "$D" ] && echo $(( $(cat /etc/total_down 2>/dev/null || echo 0) + D )) > /etc/total_down
    [ -n "$U" ] && echo $(( $(cat /etc/total_up 2>/dev/null || echo 0) + U )) > /etc/total_up
    
    systemctl stop tunnel; wg-quick down wg0; ip link delete wg0 2>/dev/null; systemctl start tunnel; sleep 5; wg-quick up wg0
    
    C=$(cat /etc/tunnel_reset_count 2>/dev/null || echo 0); echo $((C + 1)) > /etc/tunnel_reset_count
    
    [ -n "$TOKEN" ] && curl -sk -X POST "$TG_URL/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=🚨 *Auto-Heal Alarm*%0A🖥 *Host:* $(hostname)%0A🔄 *Status:* Tunnel Recovered (High Latency or Link Down)" -d "parse_mode=Markdown" >/dev/null 2>&1
fi

if [ "$(date +%H:%M)" == "00:00" ]; then
    RC=$(cat /etc/tunnel_reset_count 2>/dev/null || echo 0)
    S=$(wg show wg0 transfer 2>/dev/null); CD=$(echo $S | awk '{print $2}' | sed 's/[^0-9]//g'); CU=$(echo $S | awk '{print $5}' | sed 's/[^0-9]//g')
    TD=$(( $(cat /etc/total_down 2>/dev/null || echo 0) + ${CD:-0} )); TU=$(( $(cat /etc/total_up 2>/dev/null || echo 0) + ${CU:-0} ))
    [ -n "$TOKEN" ] && curl -sk -X POST "$TG_URL/bot$TOKEN/sendMessage" -d "chat_id=$CHATID" -d "text=📊 Daily Report%0A🔁 Resets: $RC%0A📥 Total Down: $((TD/1048576)) MB%0A📤 Total Up: $((TU/1048576)) MB" >/dev/null 2>&1
    echo "0" > /etc/tunnel_reset_count; echo "0" > /etc/total_down; echo "0" > /etc/total_up
fi
EOF
    chmod +x $HEALER_SCRIPT
    (crontab -l 2>/dev/null | grep -v "tunnel_healer.sh"; echo "* * * * * $HEALER_SCRIPT") | crontab -
    echo -e "${GREEN}✔ Ultimate Healer installed (Sensitivity: 300ms).${NC}"
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
    echo -e "${WHITE}               [ MASTER TUNNEL PRO v1.02 ]${NC}"
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
    echo -e "${WHITE}               [ MASTER TUNNEL PRO v1.02 ]${NC}"
    echo -e "${CYAN}========================================================${NC}"
echo "1) Install/Update Tunnel (Core)"
echo "2) Port Forwarder (GOST / HAProxy)"
echo "3) Telegram Bot Settings"
echo "4) Anti-Lag Auto-Healer"
echo "5) Daily Traffic Report"
echo "6) Show Full System Status"
echo "7) Uninstall"
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
    5) send_daily_report ;;
    6) show_status ;;
    7)  
            clear
            echo -e "${RED}>>> Uninstall Management <<<${NC}"
            echo "1) Uninstall Everything (Full Reset)"
            echo "2) Remove Only Auto-Healer"
            echo "3) Remove Only Telegram Settings"
            echo "4) Remove Only Port Forwards (GOST/HAProxy)"
            echo "5) Back"
            read -p "Select [1-5]: " un_opt
            
            case $un_opt in
                1)
                    systemctl stop tunnel gost-* haproxy 2>/dev/null
                    systemctl disable tunnel gost-* 2>/dev/null
                    wg-quick down wg0 2>/dev/null
                    rm -rf /etc/wireguard /opt/udp2raw /etc/systemd/system/tunnel.service /etc/systemd/system/gost-*.service
                    rm -f /etc/sysctl.d/99-tunnel.conf $HEALER_SCRIPT $TELEGRAM_CONF
                    crontab -l 2>/dev/null | grep -v "tunnel_healer.sh" | crontab -
                    echo -e "${RED}✔ All components uninstalled.${NC}"
                    sleep 2 ;;
                2)
                    crontab -l 2>/dev/null | grep -v "tunnel_healer.sh" | crontab -
                    rm -f $HEALER_SCRIPT
                    echo -e "${YELLOW}✔ Auto-Healer removed from Cron and System.${NC}"
                    sleep 2 ;;
                3)
                    rm -f $TELEGRAM_CONF
                    echo -e "${YELLOW}✔ Telegram configuration cleared.${NC}"
                    sleep 2 ;;
                4)
                    systemctl stop gost-* 2>/dev/null
                    systemctl disable gost-* 2>/dev/null
                    rm -f /etc/systemd/system/gost-*.service
                    [ -f $HAPROXY_CONF ] && echo "" > $HAPROXY_CONF && systemctl restart haproxy
                    systemctl daemon-reload
                    echo -e "${YELLOW}✔ All port forwards cleared.${NC}"
                    sleep 2 ;;
                5) continue ;;
            esac
            ;;
    8) exit 0 ;;
esac
done

