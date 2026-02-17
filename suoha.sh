#!/bin/bash
# onekey suoha
# 修改：
#   1. 替换失效的 speed.cloudflare.com/meta 为新接口
#   2. 纯 IPv6 环境自动检测并配置 NAT64，保证 GitHub 等 IPv4 资源可下载
#   3. 脚本结束后自动回滚临时 NAT64 配置（可选）

# ─────────────────────────────────────────────
# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─────────────────────────────────────────────
# 1. 检测网络环境：是否纯 IPv6（无 IPv4）
# ─────────────────────────────────────────────
HAS_IPV4=false
HAS_IPV6=false
NAT64_APPLIED=false   # 标记是否由本脚本临时写入了 NAT64

check_network() {
    # 尝试通过 IPv4 访问 Cloudflare IPv4 检测接口
    if curl -4 -s --max-time 5 https://ipv4-check-perf.radar.cloudflare.com/ -o /dev/null 2>/dev/null; then
        HAS_IPV4=true
    fi
    # 尝试通过 IPv6 访问 Cloudflare IPv6 检测接口
    if curl -6 -s --max-time 5 https://ipv6-check-perf.radar.cloudflare.com/ -o /dev/null 2>/dev/null; then
        HAS_IPV6=true
    fi

    if [ "$HAS_IPV4" = true ] && [ "$HAS_IPV6" = true ]; then
        ips="auto"
        info "检测到双栈网络（IPv4 + IPv6）"
    elif [ "$HAS_IPV4" = true ] && [ "$HAS_IPV6" = false ]; then
        ips="4"
        info "检测到纯 IPv4 网络"
    elif [ "$HAS_IPV4" = false ] && [ "$HAS_IPV6" = true ]; then
        ips="6"
        warn "检测到纯 IPv6 网络，将配置 NAT64 以访问 IPv4 资源（GitHub 等）"
        setup_nat64
    else
        err "网络异常：IPv4 和 IPv6 均无法连通，请检查网络配置。"
    fi
}

# ─────────────────────────────────────────────
# 2. 自动配置 NAT64（仅纯 IPv6 时调用）
# ─────────────────────────────────────────────
# NAT64 服务商列表（按优先级）
NAT64_PROVIDERS=(
    "2a00:1098:2b::1"
    "2a00:1098:2c::1"
    "2001:67c:2960::64"
    "2001:67c:2b0::4"
    "2602:fc59:b0:9e::64"
)

setup_nat64() {
    info "开始自动寻找可用的公共 NAT64/DNS64 服务商..."
    local chosen=""

    for dns in "${NAT64_PROVIDERS[@]}"; do
        info "测试 $dns ..."
        # 通过该 DNS64 解析 ipv4only.arpa，看能否得到合成 AAAA 地址
        local result
        if command -v dig &>/dev/null; then
            result=$(dig -6 @"${dns}" AAAA ipv4only.arpa +short +time=3 +tries=1 2>/dev/null | head -1)
        else
            result=$(nslookup -type=AAAA ipv4only.arpa "${dns}" 2>/dev/null | grep -o '[0-9a-f:]\{10,\}' | head -1)
        fi
        if [ -n "$result" ]; then
            ok "找到可用 NAT64: $dns（合成地址: $result）"
            chosen="$dns"
            break
        fi
    done

    if [ -z "$chosen" ]; then
        err "所有 NAT64 服务商均不可达！请检查 IPv6 网络或手动配置 NAT64 后重试。"
    fi

    # 备份并写入临时 DNS
    _nat64_backup_and_apply "$chosen"
}

_nat64_backup_and_apply() {
    local dns1="$1"
    local dns2="${2:-2a00:1098:2c::1}"  # 默认备用

    # 解除可能的不可变标志
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # 备份（只备份一次，防止多次调用覆盖备份）
    if [ ! -f /etc/resolv.conf.suoha.bak ]; then
        cp /etc/resolv.conf /etc/resolv.conf.suoha.bak
        info "已备份原 DNS 配置 -> /etc/resolv.conf.suoha.bak"
    fi

    # 写入 NAT64 DNS
    cat > /etc/resolv.conf <<EOF
# Temporary NAT64/DNS64 by suoha.sh
nameserver ${dns1}
nameserver ${dns2}
EOF
    NAT64_APPLIED=true
    ok "NAT64 DNS 已写入，后续下载将通过 NAT64 访问 IPv4 资源。"

    # 等待 DNS 生效，验证能否解析 github.com
    local retry=0
    while [ $retry -lt 10 ]; do
        if getent hosts github.com &>/dev/null || curl -s --max-time 5 https://github.com -o /dev/null 2>/dev/null; then
            ok "NAT64 验证通过，可以访问 github.com"
            return
        fi
        retry=$((retry+1))
        sleep 1
    done
    warn "NAT64 配置后仍无法访问 github.com，继续尝试（可能会导致下载失败）"
}

# 脚本结束时恢复原始 DNS（使用 trap 确保退出时执行）
_restore_dns() {
    if [ "$NAT64_APPLIED" = true ] && [ -f /etc/resolv.conf.suoha.bak ]; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
        cp /etc/resolv.conf.suoha.bak /etc/resolv.conf
        rm -f /etc/resolv.conf.suoha.bak
        info "已恢复原始 DNS 配置。"
    fi
}
trap _restore_dns EXIT

# ─────────────────────────────────────────────
# 3. 获取 ISP 信息（替换失效的 speed.cloudflare.com/meta）
# ─────────────────────────────────────────────
get_isp_info() {
    local raw=""
    local country asn org city

    if [ "$HAS_IPV4" = true ]; then
        # 优先用 IPv4 接口（字段：country, asn, city, colo）
        raw=$(curl -4 -s --max-time 8 https://ipv4-check-perf.radar.cloudflare.com/ 2>/dev/null)
    fi

    # 如果 IPv4 接口拿不到，尝试 IPv6 接口（通过 NAT64 或双栈）
    if [ -z "$raw" ]; then
        raw=$(curl -s --max-time 8 https://ipv6-check-perf.radar.cloudflare.com/ 2>/dev/null)
    fi

    # 兜底：用 ip.sb 获取简单信息
    if [ -z "$raw" ]; then
        warn "Cloudflare Radar 接口无响应，使用备用接口获取信息"
        local ip_addr
        ip_addr=$(curl -s --max-time 5 https://api4.ipify.org 2>/dev/null || curl -s --max-time 5 https://api6.ipify.org 2>/dev/null || echo "unknown")
        isp="Unknown_AS0_Unknown"
        info "无法获取完整 ISP 信息，使用默认标识: $isp"
        return
    fi

    # 解析 JSON 字段（使用 awk/sed，无需 jq）
    country=$(echo "$raw" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
    asn=$(echo "$raw" | grep -o '"asn":[0-9]*' | grep -o '[0-9]*')
    city=$(echo "$raw" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
    # colo 是机房代号，作为运营商补充
    local colo
    colo=$(echo "$raw" | grep -o '"colo":"[^"]*"' | cut -d'"' -f4)

    # 拼接成原脚本期望的格式：国家_ASN_城市/机房  （下划线分隔，无空格）
    local org_part="${city:-${colo:-Unknown}}"
    isp="${country:-Unknown}_AS${asn:-0}_${org_part// /_}"

    ok "ISP 信息: $isp"
}

# ─────────────────────────────────────────────
# 4. 原脚本：系统检测与依赖安装
# ─────────────────────────────────────────────
linux_os=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
linux_update=("apt update" "apt update" "yum -y update" "yum -y update" "apk update")
linux_install=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add -f")
n=0
for i in $(echo ${linux_os[@]}); do
    if [ "$i" == "$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}')" ]; then
        break
    else
        n=$[$n+1]
    fi
done
if [ $n == 5 ]; then
    echo 当前系统$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2)没有适配
    echo 默认使用APT包管理器
    n=0
fi

# 安装依赖（curl/unzip/dig）
_ensure_pkg() {
    local pkg="$1"
    if [ -z "$(type -P $pkg)" ]; then
        info "安装 $pkg..."
        ${linux_update[$n]} >/dev/null 2>&1
        ${linux_install[$n]} "$pkg" >/dev/null 2>&1
    fi
}
_ensure_pkg curl
_ensure_pkg unzip
# dig 属于 dnsutils(debian) / bind-utils(centos) / bind-tools(alpine)
if [ -z "$(type -P dig)" ]; then
    case "${linux_os[$n]}" in
        Debian|Ubuntu) ${linux_install[$n]} dnsutils >/dev/null 2>&1 ;;
        CentOS|Fedora) ${linux_install[$n]} bind-utils >/dev/null 2>&1 ;;
        Alpine)        ${linux_install[$n]} bind-tools >/dev/null 2>&1 ;;
    esac
fi
if [ "$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}')" != "Alpine" ]; then
    _ensure_pkg systemctl
fi

# ─────────────────────────────────────────────
# 5. 执行网络检测 & 获取 ISP（在安装依赖之后）
# ─────────────────────────────────────────────
check_network
get_isp_info

# ─────────────────────────────────────────────
# 6. 原有功能函数（quicktunnel / installtunnel）保持不变
# ─────────────────────────────────────────────

function quicktunnel(){
rm -rf xray cloudflared-linux xray.zip
case "$(uname -m)" in
    x86_64 | x64 | amd64 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared-linux
    ;;
    i386 | i686 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-32.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o cloudflared-linux
    ;;
    armv8 | arm64 | aarch64 )
    echo arm64
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared-linux
    ;;
    armv7l )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm32-v7a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -o cloudflared-linux
    ;;
    * )
    echo 当前架构$(uname -m)没有适配
    exit
    ;;
esac
mkdir xray
unzip -d xray xray.zip
chmod +x cloudflared-linux xray/xray
rm -rf xray.zip
uuid=$(cat /proc/sys/kernel/random/uuid)
urlpath=$(echo $uuid | awk -F- '{print $1}')
port=$[$RANDOM+10000]
if [ $protocol == 1 ]
then
cat>xray/config.json<<EOF
{
	"inbounds": [
		{
			"port": $port,
			"listen": "localhost",
			"protocol": "vmess",
			"settings": {
				"clients": [
					{
						"id": "$uuid",
						"alterId": 0
					}
				]
			},
			"streamSettings": {
				"network": "ws",
				"wsSettings": {
					"path": "$urlpath"
				}
			}
		}
	],
	"outbounds": [
		{
			"protocol": "freedom",
			"settings": {}
		}
	]
}
EOF
fi
if [ $protocol == 2 ]
then
cat>xray/config.json<<EOF
{
	"inbounds": [
		{
			"port": $port,
			"listen": "localhost",
			"protocol": "vless",
			"settings": {
				"decryption": "none",
				"clients": [
					{
						"id": "$uuid"
					}
				]
			},
			"streamSettings": {
				"network": "ws",
				"wsSettings": {
					"path": "$urlpath"
				}
			}
		}
	],
	"outbounds": [
		{
			"protocol": "freedom",
			"settings": {}
		}
	]
}
EOF
fi
./xray/xray run>/dev/null 2>&1 &
./cloudflared-linux tunnel --url http://localhost:$port --no-autoupdate --edge-ip-version $ips --protocol http2 >argo.log 2>&1 &
sleep 1
n=0
while true
do
n=$[$n+1]
clear
echo 等待cloudflare argo生成地址 已等待 $n 秒
argo=$(cat argo.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
if [ $n == 15 ]
then
	n=0
	if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
	then
		kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	else
		kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
	fi
	rm -rf argo.log
	clear
	echo argo获取超时,重试中
	./cloudflared-linux tunnel --url http://localhost:$port --no-autoupdate --edge-ip-version $ips --protocol http2 >argo.log 2>&1 &
	sleep 1
elif [ -z "$argo" ]
then
	sleep 1
else
	rm -rf argo.log
	break
fi
done
clear
if [ $protocol == 1 ]
then
	echo -e vmess链接已经生成, lo.cafe 可替换为CF优选IP'\n' > v2ray.txt
	if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
	then
		echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$argo'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"443","ps":"'$(echo $isp | sed -e 's/_/ /g')'_tls","tls":"tls","type":"none","v":"2"}' | base64 | awk '{ORS=(NR%76==0?RS:"");}1') >> v2ray.txt
	else
		echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$argo'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"443","ps":"'$(echo $isp | sed -e 's/_/ /g')'_tls","tls":"tls","type":"none","v":"2"}' | base64 -w 0) >> v2ray.txt
	fi
	echo -e '\n'端口 443 可改为 2053 2083 2087 2096 8443'\n' >> v2ray.txt
	if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
	then
		echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$argo'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"80","ps":"'$(echo $isp | sed -e 's/_/ /g')'","tls":"","type":"none","v":"2"}' | base64 | awk '{ORS=(NR%76==0?RS:"");}1') >> v2ray.txt
	else
		echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$argo'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"80","ps":"'$(echo $isp | sed -e 's/_/ /g')'","tls":"","type":"none","v":"2"}' | base64 -w 0) >> v2ray.txt
	fi
	echo -e '\n'端口 80 可改为 8080 8880 2052 2082 2086 2095 >> v2ray.txt
fi
if [ $protocol == 2 ]
then
	echo -e vless链接已经生成, lo.cafe 可替换为CF优选IP'\n' > v2ray.txt
	echo 'vless://'$uuid'@lo.cafe:443?encryption=none&security=tls&type=ws&host='$argo'&path='$urlpath'#'$(echo $isp | sed -e 's/_/%20/g' -e 's/,/%2C/g')'_tls' >> v2ray.txt
	echo -e '\n'端口 443 可改为 2053 2083 2087 2096 8443'\n' >> v2ray.txt
	echo 'vless://'$uuid'@lo.cafe:80?encryption=none&security=none&type=ws&host='$argo'&path='$urlpath'#'$(echo $isp | sed -e 's/_/%20/g' -e 's/,/%2C/g')'' >> v2ray.txt
	echo -e '\n'端口 80 可改为 8080 8880 2052 2082 2086 2095 >> v2ray.txt
fi
rm -rf argo.log
cat v2ray.txt
echo -e '\n'信息已经保存在 v2ray.txt,再次查看请运行 cat v2ray.txt
}

function installtunnel(){
#创建主目录
mkdir -p /opt/suoha/ >/dev/null 2>&1
rm -rf xray cloudflared-linux xray.zip
case "$(uname -m)" in
    x86_64 | x64 | amd64 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared-linux
    ;;
    i386 | i686 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-32.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o cloudflared-linux
    ;;
    armv8 | arm64 | aarch64 )
    echo arm64
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared-linux
    ;;
    armv7l )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm32-v7a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -o cloudflared-linux
    ;;
    * )
    echo 当前架构$(uname -m)没有适配
    exit
    ;;
esac
mkdir xray
unzip -d xray xray.zip
chmod +x cloudflared-linux xray/xray
mv cloudflared-linux /opt/suoha/
mv xray/xray /opt/suoha/
rm -rf xray xray.zip
uuid=$(cat /proc/sys/kernel/random/uuid)
urlpath=$(echo $uuid | awk -F- '{print $1}')
port=$[$RANDOM+10000]
if [ $protocol == 1 ]
then
cat>/opt/suoha/config.json<<EOF
{
	"inbounds": [
		{
			"port": $port,
			"listen": "localhost",
			"protocol": "vmess",
			"settings": {
				"clients": [
					{
						"id": "$uuid",
						"alterId": 0
					}
				]
			},
			"streamSettings": {
				"network": "ws",
				"wsSettings": {
					"path": "$urlpath"
				}
			}
		}
	],
	"outbounds": [
		{
			"protocol": "freedom",
			"settings": {}
		}
	]
}
EOF
fi
if [ $protocol == 2 ]
then
cat>/opt/suoha/config.json<<EOF
{
	"inbounds": [
		{
			"port": $port,
			"listen": "localhost",
			"protocol": "vless",
			"settings": {
				"decryption": "none",
				"clients": [
					{
						"id": "$uuid"
					}
				]
			},
			"streamSettings": {
				"network": "ws",
				"wsSettings": {
					"path": "$urlpath"
				}
			}
		}
	],
	"outbounds": [
		{
			"protocol": "freedom",
			"settings": {}
		}
	]
}
EOF
fi
clear
echo 复制下面的链接,用浏览器打开并授权需要绑定的域名
echo 在网页中授权完毕后会继续进行下一步设置
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel login
clear
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel list >argo.log 2>&1
echo -e ARGO TUNNEL当前已经绑定的服务如下'\n'
sed 1,2d argo.log | awk '{print $2}'
echo -e '\n'自定义一个完整二级域名,例如 xxx.example.com
echo 必须是网页里面绑定授权的域名才生效,不能乱输入
read -p "输入绑定域名的完整二级域名: " domain
if [ -z "$domain" ]
then
	echo 没有设置域名
	exit
elif [ $(echo $domain | grep "\." | wc -l) == 0 ]
then
	echo 域名格式不正确
	exit
fi
name=$(echo $domain | awk -F\. '{print $1}')
if [ $(sed 1,2d argo.log | awk '{print $2}' | grep -w $name | wc -l) == 0 ]
then
	echo 创建TUNNEL $name
	/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel create $name >argo.log 2>&1
	echo TUNNEL $name 创建成功
else
	echo TUNNEL $name 已经存在
	if [ ! -f "/root/.cloudflared/$(sed 1,2d argo.log | awk '{print $1" "$2}' | grep -w $name | awk '{print $1}').json" ]
	then
		echo /root/.cloudflared/$(sed 1,2d argo.log | awk '{print $1" "$2}' | grep -w $name | awk '{print $1}').json 文件不存在
		echo 清理TUNNEL $name
		/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel cleanup $name >argo.log 2>&1
		echo 删除TUNNEL $name
		/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel delete $name >argo.log 2>&1
		echo 重建TUNNEL $name
		/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel create $name >argo.log 2>&1
	else
		echo 清理TUNNEL $name
		/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel cleanup $name >argo.log 2>&1
	fi
fi
echo 绑定 TUNNEL $name 到域名 $domain
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel route dns --overwrite-dns $name $domain >argo.log 2>&1
echo $domain 绑定成功
tunneluuid=$(cut -d= -f2 argo.log)
if [ $protocol == 1 ]
then
	echo -e vmess链接已经生成, lo.cafe 可替换为CF优选IP'\n' >/opt/suoha/v2ray.txt
	echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$domain'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"443","ps":"'$(echo $isp | sed -e 's/_/ /g')'","tls":"tls","type":"none","v":"2"}' | base64 -w 0) >>/opt/suoha/v2ray.txt
	echo -e '\n'端口 443 可改为 2053 2083 2087 2096 8443'\n' >>/opt/suoha/v2ray.txt
	echo 'vmess://'$(echo '{"add":"lo.cafe","aid":"0","host":"'$domain'","id":"'$uuid'","net":"ws","path":"'$urlpath'","port":"80","ps":"'$(echo $isp | sed -e 's/_/ /g')'","tls":"","type":"none","v":"2"}' | base64 -w 0) >>/opt/suoha/v2ray.txt
	echo -e '\n'端口 80 可改为 8080 8880 2052 2082 2086 2095'\n' >>/opt/suoha/v2ray.txt
	echo 注意:如果 80 8080 8880 2052 2082 2086 2095 端口无法正常使用 >>/opt/suoha/v2ray.txt
	echo 请前往 https://dash.cloudflare.com/ >>/opt/suoha/v2ray.txt
	echo 检查管理面板 SSL/TLS - 边缘证书 - 始终使用HTTPS 是否处于关闭状态 >>/opt/suoha/v2ray.txt
fi
if [ $protocol == 2 ]
then
	echo -e vless链接已经生成, lo.cafe 可替换为CF优选IP'\n' >/opt/suoha/v2ray.txt
	echo 'vless://'$uuid'@lo.cafe:443?encryption=none&security=tls&type=ws&host='$domain'&path='$urlpath'#'$(echo $isp | sed -e 's/_/%20/g' -e 's/,/%2C/g')'_tls' >>/opt/suoha/v2ray.txt
	echo -e '\n'端口 443 可改为 2053 2083 2087 2096 8443'\n' >>/opt/suoha/v2ray.txt
	echo 'vless://'$uuid'@lo.cafe:80?encryption=none&security=none&type=ws&host='$domain'&path='$urlpath'#'$(echo $isp | sed -e 's/_/%20/g' -e 's/,/%2C/g')'' >>/opt/suoha/v2ray.txt
	echo -e '\n'端口 80 可改为 8080 8880 2052 2082 2086 2095'\n' >>/opt/suoha/v2ray.txt
	echo 注意:如果 80 8080 8880 2052 2082 2086 2095 端口无法正常使用 >>/opt/suoha/v2ray.txt
	echo 请前往 https://dash.cloudflare.com/ >>/opt/suoha/v2ray.txt
	echo 检查管理面板 SSL/TLS - 边缘证书 - 始终使用HTTPS 是否处于关闭状态 >>/opt/suoha/v2ray.txt
fi
rm -rf argo.log
cat>/opt/suoha/config.yaml<<EOF
tunnel: $tunneluuid
credentials-file: /root/.cloudflared/$tunneluuid.json

ingress:
  - hostname:
    service: http://localhost:$port
EOF
if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
then
cat>/etc/local.d/cloudflared.start<<EOF
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/suoha/config.yaml run $name &
EOF
cat>/etc/local.d/xray.start<<EOF
/opt/suoha/xray run -config /opt/suoha/config.json &
EOF
chmod +x /etc/local.d/cloudflared.start /etc/local.d/xray.start
rc-update add local
/etc/local.d/cloudflared.start >/dev/null 2>&1
/etc/local.d/xray.start >/dev/null 2>&1
else
#创建服务
cat>/lib/systemd/system/cloudflared.service<<EOF
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
cat>/lib/systemd/system/xray.service<<EOF
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
systemctl enable cloudflared.service >/dev/null 2>&1
systemctl enable xray.service >/dev/null 2>&1
systemctl --system daemon-reload
systemctl start cloudflared.service
systemctl start xray.service
fi

#创建管理脚本
if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
then
cat>/opt/suoha/suoha.sh<<'MGMTEOF'
#!/bin/bash
while true
do
if [ $(ps -ef | grep cloudflared-linux | grep -v grep | wc -l) == 0 ]
then
	argostatus=stop
else
	argostatus=running
fi
if [ $(ps -ef | grep xray | grep -v grep | wc -l) == 0 ]
then
	xraystatus=stop
else
	xraystatus=running
fi
echo argo $argostatus
echo xray $xraystatus
echo 1.管理TUNNEL
echo 2.启动服务
echo 3.停止服务
echo 4.重启服务
echo 5.卸载服务
echo 6.查看当前v2ray链接
echo 0.退出
read -p "请选择菜单(默认0): " menu
if [ -z "$menu" ]
then
	menu=0
fi
if [ $menu == 1 ]
then
	clear
	while true
	do
		echo ARGO TUNNEL当前已经绑定的服务如下
		/opt/suoha/cloudflared-linux tunnel list
		echo 1.删除TUNNEL
		echo 0.退出
		read -p "请选择菜单(默认0): " tunneladmin
		if [ -z "$tunneladmin" ]
		then
			tunneladmin=0
		fi
		if [ $tunneladmin == 1 ]
		then
			read -p "请输入要删除的TUNNEL NAME: " tunnelname
			echo 断开TUNNEL $tunnelname
			/opt/suoha/cloudflared-linux tunnel cleanup $tunnelname
			echo 删除TUNNEL $tunnelname
			/opt/suoha/cloudflared-linux tunnel delete $tunnelname
		else
			break
		fi
	done
elif [ $menu == 2 ]
then
	kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	/etc/local.d/cloudflared.start >/dev/null 2>&1
	/etc/local.d/xray.start >/dev/null 2>&1
	clear
	sleep 1
elif [ $menu == 3 ]
then
	kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	clear
	sleep 2
elif [ $menu == 4 ]
then
	kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	/etc/local.d/cloudflared.start >/dev/null 2>&1
	/etc/local.d/xray.start >/dev/null 2>&1
	clear
	sleep 1
elif [ $menu == 5 ]
then
	kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	rm -rf /opt/suoha /etc/local.d/cloudflared.start /etc/local.d/xray.start /usr/bin/suoha ~/.cloudflared
	echo 所有服务都卸载完成
	echo 彻底删除授权记录
	echo 请访问 https://dash.cloudflare.com/profile/api-tokens
	echo 删除授权的 Argo Tunnel API Token 即可
	exit
elif [ $menu == 6 ]
then
	clear
	cat /opt/suoha/v2ray.txt
elif [ $menu == 0 ]
then
	echo 退出成功
	exit
fi
done
MGMTEOF
else
cat>/opt/suoha/suoha.sh<<'MGMTEOF'
#!/bin/bash
clear
while true
do
echo argo $(systemctl status cloudflared.service | sed -n '3p')
echo xray $(systemctl status xray.service | sed -n '3p')
echo 1.管理TUNNEL
echo 2.启动服务
echo 3.停止服务
echo 4.重启服务
echo 5.卸载服务
echo 6.查看当前v2ray链接
echo 0.退出
read -p "请选择菜单(默认0): " menu
if [ -z "$menu" ]
then
	menu=0
fi
if [ $menu == 1 ]
then
	clear
	while true
	do
		echo ARGO TUNNEL当前已经绑定的服务如下
		/opt/suoha/cloudflared-linux tunnel list
		echo 1.删除TUNNEL
		echo 0.退出
		read -p "请选择菜单(默认0): " tunneladmin
		if [ -z "$tunneladmin" ]
		then
			tunneladmin=0
		fi
		if [ $tunneladmin == 1 ]
		then
			read -p "请输入要删除的TUNNEL NAME: " tunnelname
			echo 断开TUNNEL $tunnelname
			/opt/suoha/cloudflared-linux tunnel cleanup $tunnelname
			echo 删除TUNNEL $tunnelname
			/opt/suoha/cloudflared-linux tunnel delete $tunnelname
		else
			break
		fi
	done
elif [ $menu == 2 ]
then
	systemctl start cloudflared.service
	systemctl start xray.service
	clear
elif [ $menu == 3 ]
then
	systemctl stop cloudflared.service
	systemctl stop xray.service
	clear
elif [ $menu == 4 ]
then
	systemctl restart cloudflared.service
	systemctl restart xray.service
	clear
elif [ $menu == 5 ]
then
	systemctl stop cloudflared.service
	systemctl stop xray.service
	systemctl disable cloudflared.service
	systemctl disable xray.service
	rm -rf /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service /opt/suoha /usr/bin/suoha ~/.cloudflared
	systemctl --system daemon-reload
	echo 所有服务都卸载完成
	echo 彻底删除授权记录
	echo 请访问 https://dash.cloudflare.com/profile/api-tokens
	echo 删除授权的 Argo Tunnel API Token 即可
	exit
elif [ $menu == 6 ]
then
	clear
	cat /opt/suoha/v2ray.txt
elif [ $menu == 0 ]
then
	echo 退出成功
	exit
fi
clear
done
MGMTEOF
fi
chmod +x /opt/suoha/suoha.sh
ln -sf /opt/suoha/suoha.sh /usr/bin/suoha
cat /opt/suoha/v2ray.txt
echo -e '\n'信息已经保存在 /opt/suoha/v2ray.txt,再次查看请运行 cat /opt/suoha/v2ray.txt
echo -e '\n'后续管理请运行 suoha
}

# ─────────────────────────────────────────────
# 7. 主菜单（与原脚本一致）
# ─────────────────────────────────────────────
clear
echo 当前ISP信息: $(echo $isp | sed 's/_/ /g')
echo 当前网络模式: $ips
echo ""
echo 请选择安装模式
echo 1.快速模式（使用 trycloudflare 免费域名，重启后地址会变化）
echo 2.隧道模式（绑定自有域名，重启后地址不变，需要CF账号）
read -p "请选择菜单(默认1): " mode
if [ -z "$mode" ]
then
	mode=1
fi
echo ""
echo 请选择协议
echo 1.vmess
echo 2.vless
read -p "请选择菜单(默认1): " protocol
if [ -z "$protocol" ]
then
	protocol=1
fi
if [ $mode == 1 ]
then
	quicktunnel
elif [ $mode == 2 ]
then
	installtunnel
fi
