#!/bin/bash
# onekey suoha - 改进版
# 修复：IP 接口替换、纯 IPv6 NAT64、双栈 IP 版本选择、DNS 恢复询问
# 新增：opera-proxy 安装（仅 IPv4/双栈）、Cloudflare WARP（IPv6/双栈）

# ─────────────────────────────────────────────
# 颜色 & 工具函数
# ─────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR ]${NC}  $*"; exit 1; }
title() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}\n"; }

# ─────────────────────────────────────────────
# 系统检测 & 依赖安装
# ─────────────────────────────────────────────
linux_os=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
linux_update=("apt-get -y update" "apt-get -y update" "yum -y update" "yum -y update" "apk update")
linux_install=("apt-get -y install" "apt-get -y install" "yum -y install" "yum -y install" "apk add -f")
PKG_N=0
for i in "${linux_os[@]}"; do
    if [ "$i" == "$(grep -i PRETTY_NAME /etc/os-release | cut -d\" -f2 | awk '{print $1}')" ]; then break; fi
    PKG_N=$((PKG_N+1))
done
if [ $PKG_N -eq 5 ]; then
    warn "系统 $(grep -i PRETTY_NAME /etc/os-release | cut -d\" -f2) 未适配，默认使用 apt"
    PKG_N=0
fi
OS_NAME=$(grep -i PRETTY_NAME /etc/os-release | cut -d\" -f2 | awk '{print $1}')

_ensure_pkg() {
    local bin="$1" pkg="${2:-$1}"
    [ -n "$(type -P "$bin")" ] && return
    info "安装 $pkg ..."
    ${linux_update[$PKG_N]} >/dev/null 2>&1
    ${linux_install[$PKG_N]} "$pkg" >/dev/null 2>&1
}
_ensure_pkg curl curl
_ensure_pkg unzip unzip
if [ "$OS_NAME" != "Alpine" ]; then _ensure_pkg systemctl systemd; fi
# dig 工具（用于 NAT64 测试）
if [ -z "$(type -P dig)" ]; then
    case "$OS_NAME" in
        Debian|Ubuntu) ${linux_install[$PKG_N]} dnsutils >/dev/null 2>&1 ;;
        CentOS|Fedora) ${linux_install[$PKG_N]} bind-utils >/dev/null 2>&1 ;;
        Alpine)        ${linux_install[$PKG_N]} bind-tools >/dev/null 2>&1 ;;
    esac
fi

# ─────────────────────────────────────────────
# 全局变量
# ─────────────────────────────────────────────
HAS_IPV4=false
HAS_IPV6=false
NAT64_APPLIED=false
ips=""       # cloudflared --edge-ip-version 参数: 4 / 6 / auto
isp=""       # 节点名称标识

# ─────────────────────────────────────────────
# NAT64 相关
# ─────────────────────────────────────────────
NAT64_DNS_LIST=(
    "2a00:1098:2b::1"
    "2a00:1098:2c::1"
    "2001:67c:2960::64"
    "2001:67c:2b0::4"
    "2602:fc59:b0:9e::64"
)

setup_nat64() {
    title "配置公共 NAT64/DNS64（让纯 IPv6 访问 IPv4）"
    local chosen=""
    for dns in "${NAT64_DNS_LIST[@]}"; do
        info "测试 $dns ..."
        local res
        if command -v dig &>/dev/null; then
            res=$(dig -6 @"$dns" AAAA ipv4only.arpa +short +time=3 +tries=1 2>/dev/null | head -1)
        else
            res=$(nslookup -type=AAAA ipv4only.arpa "$dns" 2>/dev/null | grep -o '[0-9a-f:]\{10,\}' | head -1)
        fi
        if [ -n "$res" ]; then
            ok "可用: $dns"
            chosen="$dns"
            break
        fi
    done
    [ -z "$chosen" ] && err "所有 NAT64 服务商均不可用，请检查 IPv6 网络后重试。"

    chattr -i /etc/resolv.conf 2>/dev/null || true
    [ ! -f /etc/resolv.conf.suoha.bak ] && cp /etc/resolv.conf /etc/resolv.conf.suoha.bak && info "原 DNS 已备份 -> /etc/resolv.conf.suoha.bak"
    cat > /etc/resolv.conf <<EOF
# suoha NAT64 temporary DNS
nameserver ${chosen}
nameserver 2a00:1098:2c::1
EOF
    NAT64_APPLIED=true
    ok "NAT64 DNS 已写入: $chosen"

    local retry=0
    info "等待 NAT64 生效..."
    while [ $retry -lt 12 ]; do
        curl -s --max-time 5 https://github.com -o /dev/null 2>/dev/null && { ok "NAT64 验证通过，可访问 GitHub"; return; }
        retry=$((retry+1)); sleep 1
    done
    warn "NAT64 验证超时，继续执行（下载可能失败）"
}

# 脚本结束询问是否恢复 NAT64 DNS
ask_restore_nat64() {
    [ "$NAT64_APPLIED" = false ] && return
    echo ""
    echo -e "${YELLOW}本次运行临时配置了 NAT64 DNS。${NC}"
    echo "  当前 DNS: $(grep '^nameserver' /etc/resolv.conf | head -1)"
    echo "  原始备份: /etc/resolv.conf.suoha.bak"
    read -rp "是否恢复原始 DNS 配置？[y/N]: " ans
    case "$ans" in
        y|Y)
            chattr -i /etc/resolv.conf 2>/dev/null || true
            cp /etc/resolv.conf.suoha.bak /etc/resolv.conf
            rm -f /etc/resolv.conf.suoha.bak
            ok "已恢复原始 DNS 配置"
            ;;
        *)
            info "保留 NAT64 DNS 配置"
            info "如需恢复，手动执行: cp /etc/resolv.conf.suoha.bak /etc/resolv.conf"
            ;;
    esac
}

# ─────────────────────────────────────────────
# 网络检测 & IP 版本选择
# ─────────────────────────────────────────────
check_network() {
    title "检测网络环境"
    info "检测 IPv4 ..."
    curl -4 -s --max-time 5 https://ipv4-check-perf.radar.cloudflare.com/ -o /dev/null 2>/dev/null && HAS_IPV4=true
    info "检测 IPv6 ..."
    curl -6 -s --max-time 5 https://ipv6-check-perf.radar.cloudflare.com/ -o /dev/null 2>/dev/null && HAS_IPV6=true

    if [ "$HAS_IPV4" = true ] && [ "$HAS_IPV6" = false ]; then
        ok "纯 IPv4 网络"
        ips="4"

    elif [ "$HAS_IPV4" = false ] && [ "$HAS_IPV6" = true ]; then
        ok "纯 IPv6 网络 → 自动配置 NAT64"
        setup_nat64
        ips="6"

    elif [ "$HAS_IPV4" = true ] && [ "$HAS_IPV6" = true ]; then
        ok "双栈网络（IPv4 + IPv6）"
        echo ""
        echo "  请选择 Cloudflare Tunnel 使用的 IP 版本："
        echo "    1. IPv4 优先  (--edge-ip-version 4)"
        echo "    2. IPv6 优先  (--edge-ip-version 6)"
        echo "    3. 自动选择  (--edge-ip-version auto) [默认]"
        read -rp "  请选择 [默认3]: " ipver
        case "${ipver:-3}" in
            1) ips="4" ;;
            2) ips="6" ;;
            *) ips="auto" ;;
        esac
        ok "已选择: edge-ip-version = $ips"
    else
        err "IPv4 和 IPv6 均无法连通，请检查网络配置。"
    fi
}

# ─────────────────────────────────────────────
# 从 JSON 原始响应中解析并拼接 ISP 标识
# 格式：country_city_ASasn_ipversion  例：JP_Tokyo_AS209557_IPv6
# ─────────────────────────────────────────────
_parse_isp() {
    local raw="$1"
    [ -z "$raw" ] && return 1

    local country city asn ip_version
    country=$(echo    "$raw" | grep -o '"country":"[^"]*"'    | cut -d'"' -f4)
    city=$(echo       "$raw" | grep -o '"city":"[^"]*"'       | cut -d'"' -f4)
    asn=$(echo        "$raw" | grep -o '"asn":[0-9]*'         | grep -o '[0-9]*')
    ip_version=$(echo "$raw" | grep -o '"ip_version":"[^"]*"' | cut -d'"' -f4)

    # city 可能含空格（如 "New York"），替换为下划线
    city="${city// /_}"

    [ -z "$country" ] && return 1

    echo "${country:-XX}_${city:-Unknown}_AS${asn:-0}_${ip_version:-IP}"
}

# ─────────────────────────────────────────────
# 获取 ISP 信息
# 同时尝试 IPv4 和 IPv6 两个接口，各自独立拼接
# isp      = 主要标识（根据 ips 选择）
# isp_ipv4 = IPv4 出口标识（双栈时额外显示）
# isp_ipv6 = IPv6 出口标识（双栈时额外显示）
# ─────────────────────────────────────────────
get_isp_info() {
    local raw4="" raw6="" parsed4="" parsed6=""

    # ── 获取 IPv4 出口信息 ──
    if [ "$HAS_IPV4" = true ]; then
        raw4=$(curl -4 -s --max-time 8 https://ipv4-check-perf.radar.cloudflare.com/ 2>/dev/null)
        parsed4=$(_parse_isp "$raw4")
    fi

    # ── 获取 IPv6 出口信息 ──
    # NAT64 环境（HAS_IPV4=false, HAS_IPV6=true）也需要获取：
    #   不加 -6/-4，让 DNS64+NAT64 自动路由；两个接口都尝试
    if [ "$HAS_IPV6" = true ]; then
        # 不加 -6 flag，兼容 NAT64：DNS64 会把 A 记录合成 AAAA，连接走 IPv6 socket
        raw6=$(curl -s --max-time 8 https://ipv6-check-perf.radar.cloudflare.com/ 2>/dev/null)
        parsed6=$(_parse_isp "$raw6")
        # NAT64 下 ipv6-check-perf 可能返回 ip_version=IPv4（实际走了 NAT64），
        # 再试一次带 -6 强制以确认
        if [ -z "$parsed6" ]; then
            raw6=$(curl -6 -s --max-time 8 https://ipv6-check-perf.radar.cloudflare.com/ 2>/dev/null)
            parsed6=$(_parse_isp "$raw6")
        fi
    fi

    # ── 根据 ips 选择主 isp 标识 ──
    if [ "$ips" = "4" ]; then
        isp="${parsed4:-Unknown_Unknown_AS0_IPv4}"
    elif [ "$ips" = "6" ]; then
        # 纯 IPv6 / NAT64：优先用 IPv6 接口结果
        # NAT64 时 IPv6 接口可能拿不到，则尝试通过 NAT64 访问 IPv4 接口
        if [ -z "$parsed6" ] && [ "$NAT64_APPLIED" = true ]; then
            raw6=$(curl -s --max-time 8 https://ipv4-check-perf.radar.cloudflare.com/ 2>/dev/null)
            parsed6=$(_parse_isp "$raw6")
            # 如果从 IPv4 接口获取到但 ip_version 字段是 IPv4，手动改为标注 IPv6(NAT64)
            [ -n "$parsed6" ] && parsed6="${parsed6%_*}_IPv6"
        fi
        isp="${parsed6:-Unknown_Unknown_AS0_IPv6}"
    else
        # auto 双栈：优先展示 IPv6 出口，拿不到用 IPv4
        isp="${parsed6:-${parsed4:-Unknown_Unknown_AS0_Auto}}"
    fi

    # ── 输出信息 ──
    ok "主要 ISP 标识: $isp"
    [ -n "$parsed4" ] && [ "$parsed4" != "$isp" ] && info "IPv4 出口: $parsed4"
    [ -n "$parsed6" ] && [ "$parsed6" != "$isp" ] && info "IPv6 出口: $parsed6"
}

# ─────────────────────────────────────────────
# 下载工具二进制（含重试）
# ─────────────────────────────────────────────
_dl() {
    local url="$1" out="$2" desc="${3:-文件}"
    info "下载 $desc ..."
    local retry=0
    while [ $retry -lt 3 ]; do
        curl -L --max-time 120 --retry 2 "$url" -o "$out" 2>/dev/null && { ok "$desc 下载完成"; return 0; }
        retry=$((retry+1))
        warn "下载失败，重试 ($retry/3) ..."
        sleep 2
    done
    err "下载 $desc 失败，请检查网络。"
}

# ─────────────────────────────────────────────
# 获取架构对应的下载 URL
# ─────────────────────────────────────────────
get_arch_urls() {
    case "$(uname -m)" in
        x86_64|x64|amd64)
            XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
            CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
            OPERA_URL="https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-amd64"
            ;;
        i386|i686)
            XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-32.zip"
            CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386"
            OPERA_URL="https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-386"
            ;;
        armv8|arm64|aarch64)
            XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"
            CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
            OPERA_URL="https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-arm64"
            ;;
        armv7l)
            XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm32-v7a.zip"
            CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
            OPERA_URL="https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-arm"
            ;;
        *)
            err "当前架构 $(uname -m) 未适配"
            ;;
    esac
}

# ─────────────────────────────────────────────
# 生成 Xray 配置
# ─────────────────────────────────────────────
gen_xray_config() {
    local cfgfile="$1" port="$2" uuid="$3" urlpath="$4"
    if [ "$protocol" = "1" ]; then
        cat > "$cfgfile" <<EOF
{
    "inbounds": [{
        "port": $port, "listen": "localhost",
        "protocol": "vmess",
        "settings": {"clients": [{"id": "$uuid", "alterId": 0}]},
        "streamSettings": {"network": "ws", "wsSettings": {"path": "$urlpath"}}
    }],
    "outbounds": [{"protocol": "freedom", "settings": {}}]
}
EOF
    else
        cat > "$cfgfile" <<EOF
{
    "inbounds": [{
        "port": $port, "listen": "localhost",
        "protocol": "vless",
        "settings": {"decryption": "none", "clients": [{"id": "$uuid"}]},
        "streamSettings": {"network": "ws", "wsSettings": {"path": "$urlpath"}}
    }],
    "outbounds": [{"protocol": "freedom", "settings": {}}]
}
EOF
    fi
}

# ─────────────────────────────────────────────
# 生成节点链接
# ─────────────────────────────────────────────
gen_links() {
    local outfile="$1" host="$2" uuid="$3" urlpath="$4" label="${5:-节点}"
    # isp_tag 用于节点备注：下划线分隔，不含空格，直接用于 URL fragment
    local isp_tag
    isp_tag="$isp"   # 已经是 COLO_CC_ASXXXX 格式，无需再处理

    {
    if [ "$protocol" = "1" ]; then
        echo -e "vmess 链接（$label）\n"
        # vmess JSON 内 path 和 vless URL 中 path 均直接写 /xxx，不做编码
        # query string 中 / 是合法字符（RFC3986），无需编码
        if [ "$OS_NAME" = "Alpine" ]; then
            echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$host'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"443","ps":"'$isp_tag'_tls","tls":"tls","type":"none","v":"2"}' | base64 | awk '{ORS=(NR%76==0?RS:"");}1')
        else
            echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$host'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"443","ps":"'$isp_tag'_tls","tls":"tls","type":"none","v":"2"}' | base64 -w 0)
        fi
        echo -e "\n端口 443 可改为 2053 2083 2087 2096 8443\n"
        if [ "$OS_NAME" = "Alpine" ]; then
            echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$host'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"80","ps":"'$isp_tag'","tls":"","type":"none","v":"2"}' | base64 | awk '{ORS=(NR%76==0?RS:"");}1')
        else
            echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$host'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"80","ps":"'$isp_tag'","tls":"","type":"none","v":"2"}' | base64 -w 0)
        fi
        echo -e "\n端口 80 可改为 8080 8880 2052 2082 2086 2095"
    else
        echo -e "vless 链接（$label）\n"
        # path 直接写 /xxx，不编码斜杠
        echo 'vless://'$uuid'@lo.cafe:443?encryption=none&security=tls&type=ws&host='$host'&path='$urlpath'#'$isp_tag'_tls'
        echo -e "\n端口 443 可改为 2053 2083 2087 2096 8443\n"
        echo 'vless://'$uuid'@lo.cafe:80?encryption=none&security=none&type=ws&host='$host'&path='$urlpath'#'$isp_tag
        echo -e "\n端口 80 可改为 8080 8880 2052 2082 2086 2095"
    fi
    echo -e "\nlo.cafe 可替换为 CF 优选 IP"
    echo -e "\n注意：80/8080 等非 TLS 端口无法使用时，请到 CF 面板关闭「始终使用 HTTPS」"
    } > "$outfile"
}

# ─────────────────────────────────────────────
# 快速模式（trycloudflare 临时域名）
# ─────────────────────────────────────────────
function quicktunnel(){
    title "快速模式安装"
    get_arch_urls
    rm -rf xray cloudflared-linux xray.zip
    _dl "$XRAY_URL" xray.zip "Xray-core"
    _dl "$CLOUDFLARED_URL" cloudflared-linux "cloudflared"
    mkdir xray
    unzip -q -d xray xray.zip
    chmod +x cloudflared-linux xray/xray
    rm -rf xray.zip

    local uuid port urlpath
    uuid=$(cat /proc/sys/kernel/random/uuid)
    urlpath="/$(echo "$uuid" | awk -F- '{print $1}')"
    port=$((RANDOM+10000))

    gen_xray_config xray/config.json "$port" "$uuid" "$urlpath"
    ./xray/xray run >/dev/null 2>&1 &
    ./cloudflared-linux tunnel --url "http://localhost:$port" --no-autoupdate \
        --edge-ip-version "$ips" --protocol http2 >argo.log 2>&1 &

    local n=0 argo=""
    while true; do
        n=$((n+1))
        printf "\r等待 Cloudflare Argo 生成地址... %d 秒" $n
        argo=$(grep -o '[a-z0-9-]*\.trycloudflare\.com' argo.log 2>/dev/null | head -1)
        if [ $n -ge 15 ] && [ -z "$argo" ]; then
            n=0
            if [ "$OS_NAME" = "Alpine" ]; then
                kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
            else
                kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
            fi
            rm -rf argo.log
            echo -e "\nArgo 获取超时，重试中..."
            ./cloudflared-linux tunnel --url "http://localhost:$port" --no-autoupdate \
                --edge-ip-version "$ips" --protocol http2 >argo.log 2>&1 &
            sleep 1
        elif [ -n "$argo" ]; then
            rm -rf argo.log
            break
        else
            sleep 1
        fi
    done
    echo ""

    gen_links v2ray.txt "$argo" "$uuid" "$urlpath" "trycloudflare"
    clear
    cat v2ray.txt
    echo -e "\n信息已保存至 v2ray.txt，再次查看: cat v2ray.txt"
}

# ─────────────────────────────────────────────
# 隧道模式（绑定自有域名）
# ─────────────────────────────────────────────
function installtunnel(){
    title "隧道模式安装"
    get_arch_urls
    mkdir -p /opt/suoha/
    rm -rf xray cloudflared-linux xray.zip
    _dl "$XRAY_URL" xray.zip "Xray-core"
    _dl "$CLOUDFLARED_URL" cloudflared-linux "cloudflared"
    mkdir xray
    unzip -q -d xray xray.zip
    chmod +x cloudflared-linux xray/xray
    mv cloudflared-linux /opt/suoha/
    mv xray/xray /opt/suoha/
    rm -rf xray xray.zip

    local uuid port urlpath
    uuid=$(cat /proc/sys/kernel/random/uuid)
    urlpath="/$(echo "$uuid" | awk -F- '{print $1}')"
    port=$((RANDOM+10000))

    gen_xray_config /opt/suoha/config.json "$port" "$uuid" "$urlpath"

    clear
    echo "复制下面的链接，用浏览器打开并授权需要绑定的域名"
    echo "在网页中授权完毕后会继续进行下一步"
    /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel login
    clear

    /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel list >argo.log 2>&1
    echo -e "\nARGO TUNNEL 当前已绑定的服务：\n"
    sed '1,2d' argo.log | awk '{print $2}'

    echo -e "\n自定义完整二级域名，例如 xxx.example.com"
    echo "必须是已授权的域名，否则无效"
    read -rp "输入绑定域名: " domain
    [ -z "$domain" ] && { echo "未设置域名"; exit 1; }
    [ "$(echo "$domain" | grep -c "\.")" = "0" ] && { echo "域名格式不正确"; exit 1; }

    local name
    name=$(echo "$domain" | awk -F. '{print $1}')

    if [ "$(sed '1,2d' argo.log | awk '{print $2}' | grep -cw "$name")" = "0" ]; then
        echo "创建 TUNNEL $name"
        /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel create "$name" >argo.log 2>&1
    else
        echo "TUNNEL $name 已存在"
        local tid
        tid=$(sed '1,2d' argo.log | awk '{print $1" "$2}' | grep -w "$name" | awk '{print $1}')
        if [ ! -f "/root/.cloudflared/${tid}.json" ]; then
            /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel cleanup "$name" >argo.log 2>&1
            /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel delete  "$name" >argo.log 2>&1
            /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel create  "$name" >argo.log 2>&1
        else
            /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel cleanup "$name" >argo.log 2>&1
        fi
    fi

    /opt/suoha/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel route dns --overwrite-dns "$name" "$domain" >argo.log 2>&1
    echo "$domain 绑定成功"

    local tunneluuid
    tunneluuid=$(grep -o '[a-f0-9-]\{36\}' argo.log | head -1)
    [ -z "$tunneluuid" ] && tunneluuid=$(cut -d= -f2 argo.log | head -1)

    cat > /opt/suoha/config.yaml <<EOF
tunnel: $tunneluuid
credentials-file: /root/.cloudflared/$tunneluuid.json

ingress:
  - hostname: $domain
    service: http://localhost:$port
  - service: http_status:404
EOF

    gen_links /opt/suoha/v2ray.txt "$domain" "$uuid" "$urlpath" "自有域名"

    # 创建系统服务
    if [ "$OS_NAME" = "Alpine" ]; then
        cat > /etc/local.d/cloudflared.start <<EOF
#!/bin/sh
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/suoha/config.yaml run $name &
EOF
        cat > /etc/local.d/xray.start <<EOF
#!/bin/sh
/opt/suoha/xray run -config /opt/suoha/config.json &
EOF
        chmod +x /etc/local.d/cloudflared.start /etc/local.d/xray.start
        rc-update add local 2>/dev/null
        /etc/local.d/cloudflared.start >/dev/null 2>&1
        /etc/local.d/xray.start >/dev/null 2>&1
    else
        cat > /lib/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/suoha/config.yaml run $name
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
        cat > /lib/systemd/system/xray.service <<EOF
[Unit]
Description=Xray
After=network.target
[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/suoha/xray run -config /opt/suoha/config.json
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
        systemctl enable cloudflared.service xray.service >/dev/null 2>&1
        systemctl daemon-reload
        systemctl start cloudflared.service xray.service
    fi

    install_mgmt_script
    ln -sf /opt/suoha/suoha.sh /usr/bin/suoha 2>/dev/null || true

    clear
    cat /opt/suoha/v2ray.txt
    echo -e "\n信息已保存至 /opt/suoha/v2ray.txt，再次查看: cat /opt/suoha/v2ray.txt"
    echo -e "\n后续管理请运行: suoha"
    rm -rf argo.log
}

# ─────────────────────────────────────────────
# opera-proxy 安装（仅 IPv4 可用时提供）
# ─────────────────────────────────────────────
install_opera_proxy() {
    title "安装 opera-proxy（Opera VPN HTTP 代理）"
    if [ "$HAS_IPV4" = false ]; then
        warn "当前环境无 IPv4，opera-proxy 需要 IPv4 连接 Opera 服务器。"
        read -rp "纯 IPv6 环境安装后可能无法使用，仍要继续？[y/N]: " ans
        [ "${ans,,}" != "y" ] && return
    fi

    get_arch_urls
    mkdir -p /opt/suoha/

    if [ -f /opt/suoha/opera-proxy ]; then
        warn "opera-proxy 已安装"
        if [ "$OS_NAME" != "Alpine" ] && systemctl is-active --quiet opera-proxy 2>/dev/null; then
            ok "opera-proxy 服务运行中"
            echo "  代理地址: $(grep 'ExecStart' /lib/systemd/system/opera-proxy.service 2>/dev/null | grep -o '\-bind-address [^ ]*' | cut -d' ' -f2)"
        fi
        read -rp "重新安装？[y/N]: " ans
        [ "${ans,,}" != "y" ] && return
        # 停止旧服务
        if [ "$OS_NAME" != "Alpine" ]; then
            systemctl stop opera-proxy.service 2>/dev/null || true
        else
            kill -9 $(ps -ef | grep opera-proxy | grep -v grep | awk '{print $1}') 2>/dev/null || true
        fi
    fi

    _dl "$OPERA_URL" /opt/suoha/opera-proxy "opera-proxy"
    chmod +x /opt/suoha/opera-proxy

    echo ""
    echo "  opera-proxy 监听配置"
    read -rp "  监听地址 [默认 0.0.0.0]: " op_bind
    op_bind="${op_bind:-0.0.0.0}"
    read -rp "  监听端口 [默认 18080]: " op_port
    op_port="${op_port:-18080}"
    echo "  可用地区: EU（欧洲） / AS（亚洲） / AM（美洲）"
    read -rp "  选择地区 [默认 EU]: " op_region
    op_region="${op_region:-EU}"

    if [ "$OS_NAME" = "Alpine" ]; then
        cat > /etc/local.d/opera-proxy.start <<EOF
#!/bin/sh
/opt/suoha/opera-proxy -bind-address ${op_bind}:${op_port} -country ${op_region} &
EOF
        chmod +x /etc/local.d/opera-proxy.start
        rc-update add local 2>/dev/null
        /etc/local.d/opera-proxy.start >/dev/null 2>&1
    else
        cat > /lib/systemd/system/opera-proxy.service <<EOF
[Unit]
Description=Opera Proxy
After=network.target
[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/suoha/opera-proxy -bind-address ${op_bind}:${op_port} -country ${op_region}
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
        systemctl enable opera-proxy.service >/dev/null 2>&1
        systemctl daemon-reload
        systemctl start opera-proxy.service
        sleep 1
        if systemctl is-active --quiet opera-proxy.service; then
            ok "opera-proxy 服务已启动"
        else
            warn "opera-proxy 服务启动失败，请检查: systemctl status opera-proxy"
        fi
    fi

    ok "opera-proxy 安装完成！"
    echo ""
    echo "  本地 HTTP 代理: http://${op_bind}:${op_port}"
    echo "  测试命令: curl -x http://127.0.0.1:${op_port} https://ip.sb"
    echo "  地区: $op_region  |  修改地区: 编辑服务文件中 -country 参数后重启"
}

# ─────────────────────────────────────────────
# Cloudflare WARP 安装
# ─────────────────────────────────────────────
install_warp() {
    title "安装 Cloudflare WARP"

    # 检查是否已安装
    if command -v warp-cli &>/dev/null; then
        ok "WARP 客户端已安装"
        warp-cli status 2>/dev/null || true
        read -rp "重新配置/重连 WARP？[y/N]: " ans
        if [ "${ans,,}" = "y" ]; then
            warp-cli connect 2>/dev/null
            ok "WARP 已重连"
        fi
        echo "  WARP SOCKS5 代理: 127.0.0.1:40000"
        return
    fi

    info "安装 Cloudflare WARP 客户端..."
    local install_ok=false

    case "$OS_NAME" in
        Debian|Ubuntu)
            _ensure_pkg gpg gpg
            _ensure_pkg lsb_release lsb-release
            curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
                | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
            local codename
            codename=$(lsb_release -cs 2>/dev/null || echo "bullseye")
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${codename} main" \
                > /etc/apt/sources.list.d/cloudflare-client.list
            apt-get update -qq && apt-get install -y cloudflare-warp && install_ok=true
            ;;
        CentOS|Fedora)
            curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo \
                -o /etc/yum.repos.d/cloudflare-warp.repo
            yum install -y cloudflare-warp && install_ok=true
            ;;
        *)
            warn "当前系统 $OS_NAME 不支持自动安装 WARP"
            echo "请手动参考: https://pkg.cloudflareclient.com/"
            return
            ;;
    esac

    if [ "$install_ok" = true ] && command -v warp-cli &>/dev/null; then
        systemctl enable warp-svc 2>/dev/null
        systemctl start  warp-svc 2>/dev/null
        sleep 2
        warp-cli register
        echo ""
        echo "选择 WARP 模式："
        echo "  1. proxy  - 本地 SOCKS5 代理 (127.0.0.1:40000) [默认]"
        echo "  2. warp   - 全局隧道（替换默认路由，慎用）"
        read -rp "请选择 [默认1]: " wmode
        case "${wmode:-1}" in
            2) warp-cli set-mode warp ;;
            *) warp-cli set-mode proxy ;;
        esac
        warp-cli connect
        sleep 2
        ok "WARP 安装并连接成功！"
        echo "  WARP SOCKS5 代理: 127.0.0.1:40000"
        echo "  测试命令: curl -x socks5h://127.0.0.1:40000 https://ip.sb"
        echo "  断开/重连: warp-cli disconnect / warp-cli connect"
    else
        warn "WARP 安装失败，请手动检查日志。"
    fi
}

# ─────────────────────────────────────────────
# 管理脚本生成
# ─────────────────────────────────────────────
install_mgmt_script() {
    if [ "$OS_NAME" = "Alpine" ]; then
        cat > /opt/suoha/suoha.sh <<'MGMT'
#!/bin/bash
while true; do
    if [ "$(ps -ef | grep cloudflared-linux | grep -v grep | wc -l)" = "0" ]; then argostatus=stop; else argostatus=running; fi
    if [ "$(ps -ef | grep 'xray run' | grep -v grep | wc -l)" = "0" ]; then xraystatus=stop; else xraystatus=running; fi
    echo ""; echo "argo: $argostatus | xray: $xraystatus"
    echo "1.管理TUNNEL  2.启动  3.停止  4.重启  5.卸载  6.查看链接  0.退出"
    read -rp "请选择 [默认0]: " menu; menu="${menu:-0}"
    case "$menu" in
        1) while true; do
               /opt/suoha/cloudflared-linux tunnel list
               echo "1.删除TUNNEL  0.返回"
               read -rp "选择: " ta; ta="${ta:-0}"; [ "$ta" = "1" ] || break
               read -rp "输入 TUNNEL NAME: " tname
               /opt/suoha/cloudflared-linux tunnel cleanup "$tname"
               /opt/suoha/cloudflared-linux tunnel delete  "$tname"
           done ;;
        2) kill -9 $(ps -ef | grep 'xray run\|cloudflared-linux' | grep -v grep | awk '{print $1}') 2>/dev/null
           /etc/local.d/cloudflared.start >/dev/null 2>&1
           /etc/local.d/xray.start >/dev/null 2>&1 ;;
        3) kill -9 $(ps -ef | grep 'xray run\|cloudflared-linux' | grep -v grep | awk '{print $1}') 2>/dev/null ;;
        4) kill -9 $(ps -ef | grep 'xray run\|cloudflared-linux' | grep -v grep | awk '{print $1}') 2>/dev/null
           /etc/local.d/cloudflared.start >/dev/null 2>&1; /etc/local.d/xray.start >/dev/null 2>&1 ;;
        5) kill -9 $(ps -ef | grep 'xray run\|cloudflared-linux\|opera-proxy' | grep -v grep | awk '{print $1}') 2>/dev/null
           rm -rf /opt/suoha /etc/local.d/cloudflared.start /etc/local.d/xray.start \
                  /etc/local.d/opera-proxy.start /usr/bin/suoha ~/.cloudflared
           echo "卸载完成。访问 https://dash.cloudflare.com/profile/api-tokens 删除 Token"; exit ;;
        6) cat /opt/suoha/v2ray.txt ;;
        0) exit ;;
    esac
done
MGMT
    else
        cat > /opt/suoha/suoha.sh <<'MGMT'
#!/bin/bash
clear
while true; do
    echo ""
    echo "argo: $(systemctl status cloudflared.service 2>/dev/null | sed -n '3p')"
    echo "xray: $(systemctl status xray.service 2>/dev/null | sed -n '3p')"
    [ -f /lib/systemd/system/opera-proxy.service ] && echo "opera: $(systemctl status opera-proxy.service 2>/dev/null | sed -n '3p')"
    echo "1.管理TUNNEL  2.启动  3.停止  4.重启  5.卸载  6.查看链接  0.退出"
    read -rp "请选择 [默认0]: " menu; menu="${menu:-0}"
    case "$menu" in
        1) while true; do
               /opt/suoha/cloudflared-linux tunnel list
               echo "1.删除TUNNEL  0.返回"
               read -rp "选择: " ta; ta="${ta:-0}"; [ "$ta" = "1" ] || break
               read -rp "输入 TUNNEL NAME: " tname
               /opt/suoha/cloudflared-linux tunnel cleanup "$tname"
               /opt/suoha/cloudflared-linux tunnel delete  "$tname"
           done ;;
        2) systemctl start  cloudflared.service xray.service ;;
        3) systemctl stop   cloudflared.service xray.service ;;
        4) systemctl restart cloudflared.service xray.service ;;
        5) systemctl stop    cloudflared.service xray.service
           systemctl disable cloudflared.service xray.service >/dev/null 2>&1
           systemctl stop    opera-proxy.service 2>/dev/null
           systemctl disable opera-proxy.service 2>/dev/null
           rm -rf /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service \
                  /lib/systemd/system/opera-proxy.service /opt/suoha /usr/bin/suoha ~/.cloudflared
           systemctl daemon-reload
           echo "卸载完成。访问 https://dash.cloudflare.com/profile/api-tokens 删除 Token"; exit ;;
        6) cat /opt/suoha/v2ray.txt ;;
        0) exit ;;
    esac
    clear
done
MGMT
    fi
    chmod +x /opt/suoha/suoha.sh
}

# ─────────────────────────────────────────────
# 附加工具菜单
# ─────────────────────────────────────────────
extra_tools_menu() {
    while true; do
        title "附加工具（可选安装）"
        local has_opera=false has_warp=false
        [ "$HAS_IPV4" = true ] && has_opera=true
        has_warp=true   # 两种网络都可以装 WARP

        [ "$has_opera" = true ] && echo "  1. opera-proxy  — 免费 Opera VPN HTTP 代理（需 IPv4）"
        echo "  2. Cloudflare WARP — 提供额外出口 IP（IPv4/IPv6 均可安装）"
        echo "  0. 返回"
        read -rp "请选择 [默认0]: " extra; extra="${extra:-0}"
        case "$extra" in
            1) [ "$has_opera" = true ] && install_opera_proxy || warn "当前网络不支持 opera-proxy" ;;
            2) install_warp ;;
            0) break ;;
            *) warn "无效选项" ;;
        esac
    done
}

# ─────────────────────────────────────────────
# 主流程入口
# ─────────────────────────────────────────────
[ "$(id -u)" -ne 0 ] && err "请使用 root 或 sudo 运行此脚本。"

check_network
get_isp_info

clear
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║            Suoha 一键安装脚本                    ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  ISP 信息  : $(echo "$isp" | sed 's/_/ /g')"
_net_str=""
[ "$HAS_IPV4" = true ] && _net_str="IPv4"
[ "$HAS_IPV6" = true ] && _net_str="$_net_str IPv6"
echo "  网络类型  : ${_net_str}"
echo "  CF 参数   : --edge-ip-version ${ips}"
echo ""
echo "  ── 安装模式 ──"
echo "    1. 快速模式（trycloudflare 临时域名，重启后地址变化）"
echo "    2. 隧道模式（绑定自有域名，重启后地址不变，需要 CF 账号）"
echo "    0. 退出"
echo ""
read -rp "请选择 [默认1]: " mode; mode="${mode:-1}"

echo ""
echo "  ── 协议选择 ──"
echo "    1. VMess"
echo "    2. VLESS"
read -rp "请选择 [默认1]: " protocol; protocol="${protocol:-1}"

case "$mode" in
    1) quicktunnel ;;
    2) installtunnel ;;
    0) ask_restore_nat64; exit 0 ;;
    *) warn "无效选项，使用快速模式"; quicktunnel ;;
esac

# 安装完成后，询问是否安装附加工具
echo ""
read -rp "是否安装附加工具（opera-proxy / WARP）？[y/N]: " showextra
[ "${showextra,,}" = "y" ] && extra_tools_menu

# 最后询问是否恢复 NAT64 DNS
ask_restore_nat64

echo ""
ok "全部完成！"
