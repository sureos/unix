#!/bin/bash
# onekey sing-box deployment script
# sing-box + cloudflare argo tunnel 一键部署脚本

# 支持的Linux发行版配置
linux_os=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine" "Arch")
linux_update=("apt update" "apt update" "yum -y update" "yum -y update" "apk update" "pacman -Sy")
linux_install=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add -f" "pacman -S --noconfirm")

# 检测系统类型
n=0
for i in `echo ${linux_os[@]}`
do
	current_os=$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}')
	if [ "$i" == "$current_os" ]
	then
		break
	else
		n=$[$n+1]
	fi
done

# 如果系统不在支持列表中，默认使用APT
if [ $n == 6 ]
then
	echo "当前系统 $current_os 没有完全适配"
	echo "默认使用APT包管理器"
	n=0
fi

# 安装必要的依赖包
echo "正在检查和安装必要依赖..."

if [ -z "$(type -P unzip)" ]; then
	echo "安装 unzip..."
	${linux_update[$n]} && ${linux_install[$n]} unzip
fi

if [ -z "$(type -P curl)" ]; then
	echo "安装 curl..."
	${linux_update[$n]} && ${linux_install[$n]} curl
fi

if [ -z "$(type -P jq)" ]; then
	echo "安装 jq..."
	${linux_update[$n]} && ${linux_install[$n]} jq
fi

if [ "$current_os" != "Alpine" ] && [ -z "$(type -P systemctl)" ]; then
	echo "安装 systemd..."
	${linux_update[$n]} && ${linux_install[$n]} systemd
fi

echo "依赖检查完成！"

# 网络连通性检查函数
function check_network() {
	echo "检查网络连通性..."
	
	# 检查 GitHub 连接
	if curl -s --max-time 10 https://api.github.com >/dev/null 2>&1; then
		echo "✓ GitHub 连接正常"
	else
		echo "✗ GitHub 连接失败，可能影响下载"
		echo "请检查网络连接或使用代理"
		return 1
	fi
	
	# 检查 Cloudflare 连接
	if curl -s --max-time 10 https://1.1.1.1 >/dev/null 2>&1; then
		echo "✓ Cloudflare 连接正常"
	else
		echo "✗ Cloudflare 连接失败，可能影响隧道功能"
	fi
	
	return 0
}

# 快速隧道模式函数 (临时模式)
function quicktunnel(){
	echo "=== 启动快速隧道模式 ==="
	
	# 检查网络连通性
	if ! check_network; then
		read -p "网络连接异常，是否继续？(y/N): " continue_anyway
		if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
			echo "已取消操作"
			exit 1
		fi
	fi
	
	# 清理旧文件
	rm -rf sing-box cloudflared-linux sing-box.tar.gz argo.log config.json
	
	# 根据系统架构下载对应版本
	arch=$(uname -m)
	echo "检测到系统架构: $arch"
	
	# 下载重试函数
	download_with_retry() {
		local url=$1
		local output=$2
		local max_retries=3
		local retry=0
		
		while [ $retry -lt $max_retries ]; do
			echo "尝试下载 $output (第 $((retry+1)) 次)..."
			
			# 使用 curl 下载并检查结果
			if curl -L --fail --connect-timeout 30 --max-time 300 "$url" -o "$output"; then
				echo "✓ $output 下载成功"
				
				# 验证文件是否为有效的压缩文件
				if file "$output" | grep -q "gzip compressed"; then
					echo "✓ $output 文件格式验证通过"
					return 0
				else
					echo "✗ $output 不是有效的 gzip 文件，重试..."
					rm -f "$output"
				fi
			else
				echo "✗ $output 下载失败，重试..."
				rm -f "$output"
			fi
			
			retry=$((retry + 1))
			sleep 2
		done
		
		echo "错误: $output 下载失败，已重试 $max_retries 次"
		return 1
	}
	
	case "$arch" in
		x86_64 | x64 | amd64 )
			echo "下载 sing-box x86_64 版本..."
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-amd64.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" "cloudflared-linux" || exit 1
			;;
		i386 | i686 )
			echo "下载 sing-box i386 版本..."
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-386.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386" "cloudflared-linux" || exit 1
			;;
		armv8 | arm64 | aarch64 )
			echo "下载 sing-box ARM64 版本..."
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-arm64.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" "cloudflared-linux" || exit 1
			;;
		armv7l | armv7 )
			echo "下载 sing-box ARMv7 版本..."
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-armv7.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm" "cloudflared-linux" || exit 1
			;;
		* )
			echo "错误: 当前架构 $arch 不支持"
			exit 1
			;;
	esac
	
	# 解压和设置权限
	echo "解压程序文件..."
	
	# 检查文件是否存在
	if [ ! -f "sing-box.tar.gz" ]; then
		echo "错误: sing-box.tar.gz 文件不存在"
		exit 1
	fi
	
	if [ ! -f "cloudflared-linux" ]; then
		echo "错误: cloudflared-linux 文件不存在"
		exit 1
	fi
	
	# 验证 tar.gz 文件格式
	if ! tar -tzf sing-box.tar.gz >/dev/null 2>&1; then
		echo "错误: sing-box.tar.gz 文件损坏或格式错误"
		echo "文件信息:"
		file sing-box.tar.gz
		ls -la sing-box.tar.gz
		exit 1
	fi
	
	# 解压 tar.gz 文件
	if tar -xzf sing-box.tar.gz; then
		echo "✓ sing-box.tar.gz 解压成功"
	else
		echo "错误: 解压 sing-box.tar.gz 失败"
		exit 1
	fi
	
	# 查找 sing-box 可执行文件
	sing_box_binary=$(find . -name "sing-box" -type f -executable 2>/dev/null | head -1)
	if [ -z "$sing_box_binary" ]; then
		# 如果找不到可执行文件，尝试查找任意 sing-box 文件
		sing_box_binary=$(find . -name "sing-box" -type f 2>/dev/null | head -1)
		if [ -z "$sing_box_binary" ]; then
			echo "错误: 未找到 sing-box 可执行文件"
			echo "解压后的文件列表:"
			find . -type f -name "*sing-box*" 2>/dev/null || echo "未找到任何 sing-box 相关文件"
			exit 1
		fi
	fi
	
	# 移动 sing-box 文件
	if mv "$sing_box_binary" ./sing-box; then
		echo "✓ sing-box 文件移动成功"
	else
		echo "错误: 移动 sing-box 文件失败"
		exit 1
	fi
	
	# 设置权限
	chmod +x cloudflared-linux sing-box
	
	# 清理临时文件
	rm -rf sing-box.tar.gz sing-box-* *.tar.gz
	
	# 验证文件是否可执行
	if [ ! -x "./sing-box" ]; then
		echo "错误: sing-box 文件不可执行"
		exit 1
	fi
	
	if [ ! -x "./cloudflared-linux" ]; then
		echo "错误: cloudflared-linux 文件不可执行"
		exit 1
	fi
	
	echo "✓ 所有文件准备就绪"
	
	# 生成配置参数
	uuid=$(cat /proc/sys/kernel/random/uuid)
	urlpath="/$(echo $uuid | awk -F- '{print $1}')"
	port=$((RANDOM + 10000))
	
	echo "生成配置参数:"
	echo "UUID: $uuid"
	echo "端口: $port"
	echo "路径: $urlpath"
	
	# 根据协议生成配置文件
	case "$protocol" in
		1)
			# VMess 协议配置
			cat > config.json << EOF
{
	"log": { "level": "info" },
	"inbounds": [{
		"type": "vmess",
		"tag": "vmess-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "uuid": "$uuid", "alterId": 0 }],
		"transport": {
			"type": "ws",
			"path": "$urlpath",
			"headers": { "Host": "localhost" }
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
		2)
			# VLESS 协议配置
			cat > config.json << EOF
{
	"log": { "level": "info" },
	"inbounds": [{
		"type": "vless",
		"tag": "vless-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "uuid": "$uuid" }],
		"transport": {
			"type": "ws",
			"path": "$urlpath",
			"headers": { "Host": "localhost" }
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
		3)
			# Hysteria2 协议配置 - 修复为使用HTTP传输
			cat > config.json << EOF
{
	"log": { "level": "info" },
	"inbounds": [{
		"type": "vmess",
		"tag": "vmess-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "uuid": "$uuid", "alterId": 0 }],
		"transport": {
			"type": "ws",
			"path": "$urlpath",
			"headers": { "Host": "localhost" }
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
		4)
			# TUIC v5 协议配置 - 修复为使用VLESS
			cat > config.json << EOF
{
	"log": { "level": "info" },
	"inbounds": [{
		"type": "vless",
		"tag": "vless-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "uuid": "$uuid" }],
		"transport": {
			"type": "ws",
			"path": "$urlpath",
			"headers": { "Host": "localhost" }
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
	esac
	
	# 启动服务
	echo "启动 sing-box 服务..."
	./sing-box run -c config.json >/dev/null 2>&1 &
	sing_box_pid=$!
	
	# 检查 sing-box 是否正常启动
	sleep 2
	if ! kill -0 $sing_box_pid 2>/dev/null; then
		echo "错误: sing-box 启动失败，检查配置文件"
		echo "运行诊断命令: ./sing-box check -c config.json"
		./sing-box check -c config.json
		exit 1
	fi
	
	# 检查端口是否正常监听
	if ! netstat -tuln 2>/dev/null | grep -q ":$port " && ! ss -tuln 2>/dev/null | grep -q ":$port "; then
		echo "警告: 端口 $port 未正常监听"
	else
		echo "✓ sing-box 正在监听端口 $port"
	fi
	
	echo "启动 Cloudflare Argo 隧道..."
	./cloudflared-linux tunnel --url http://127.0.0.1:$port --no-autoupdate --edge-ip-version $ips --protocol http2 >argo.log 2>&1 &
	
	# 等待隧道地址生成
	echo "等待 Cloudflare 隧道地址生成..."
	sleep 3
	
	retry_count=0
	max_retries=20
	
	while [ $retry_count -lt $max_retries ]
	do
		retry_count=$((retry_count + 1))
		clear
		echo "等待 Cloudflare Argo 生成地址，已等待 $retry_count 秒"
		
		# 提取隧道地址
		argo_url=$(cat argo.log | grep -o 'https://.*\.trycloudflare\.com' | head -1)
		argo_domain=$(echo $argo_url | sed 's|https://||')
		
		if [ $retry_count -eq 15 ]; then
			echo "隧道获取超时，重试中..."
			if [ "$current_os" == "Alpine" ]; then
				kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			else
				kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
			fi
			rm -rf argo.log
			./cloudflared-linux tunnel --url http://127.0.0.1:$port --no-autoupdate --edge-ip-version $ips --protocol http2 >argo.log 2>&1 &
			sleep 3
			retry_count=0
		elif [ -z "$argo_domain" ]; then
			sleep 1
		else
			echo "成功获取隧道地址: $argo_domain"
			break
		fi
	done
	
	if [ -z "$argo_domain" ]; then
		echo "错误: 无法获取 Cloudflare 隧道地址"
		exit 1
	fi
	
	# 生成客户端配置
	generate_client_config "$argo_domain" "$uuid" "$urlpath" "$protocol" "client-config.txt"
	
	# 显示配置
	clear
	cat client-config.txt
	echo ""
	echo "配置信息已保存到 client-config.txt 文件"
	
	# 清理日志文件
	rm -rf argo.log
}

# 生成客户端配置函数
function generate_client_config(){
	local domain=$1
	local uuid=$2
	local urlpath=$3
	local protocol=$4
	local output_file=$5
	
	# 获取ISP信息
	isp_info=$(curl -$ips -s https://speed.cloudflare.com/meta | jq -r '.asn + "-" + .city + "-" + .country' | sed 's/ /_/g' 2>/dev/null || echo "Unknown_ISP")
	
	echo "=== Sing-box 客户端配置 ===" > $output_file
	echo "域名: $domain" >> $output_file
	echo "协议: $(get_protocol_name $protocol)" >> $output_file
	echo "ISP: $isp_info" >> $output_file
	echo "" >> $output_file
	
	case "$protocol" in
		1)
			# VMess 配置
			echo "=== VMess 协议配置 ===" >> $output_file
			vmess_config='{"v":"2","ps":"'$isp_info'_TLS","add":"'$domain'","port":"443","id":"'$uuid'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$domain'","path":"'$urlpath'","tls":"tls","sni":"'$domain'"}'
			echo "vmess://$(echo $vmess_config | base64 -w 0)" >> $output_file
			echo "" >> $output_file
			echo "端口说明：443 可改为 2053 2083 2087 2096 8443" >> $output_file
			echo "" >> $output_file
			# 非 TLS 版本
			vmess_config_notls='{"v":"2","ps":"'$isp_info'","add":"'$domain'","port":"80","id":"'$uuid'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$domain'","path":"'$urlpath'","tls":"","sni":""}'
			echo "vmess://$(echo $vmess_config_notls | base64 -w 0)" >> $output_file
			echo "" >> $output_file
			echo "端口说明：80 可改为 8080 8880 2052 2082 2086 2095" >> $output_file
			;;
		2)
			# VLESS 配置
			echo "=== VLESS 协议配置 ===" >> $output_file
			echo "vless://$uuid@$domain:443?encryption=none&security=tls&type=ws&host=$domain&path=$urlpath&sni=$domain#${isp_info}_TLS" >> $output_file
			echo "" >> $output_file
			echo "端口说明：443 可改为 2053 2083 2087 2096 8443" >> $output_file
			echo "" >> $output_file
			# 非 TLS 版本
			echo "vless://$uuid@$domain:80?encryption=none&security=none&type=ws&host=$domain&path=$urlpath#${isp_info}" >> $output_file
			echo "" >> $output_file
			echo "端口说明：80 可改为 8080 8880 2052 2082 2086 2095" >> $output_file
			;;
		3)
			# Hysteria2 配置（实际使用 VMess）
			echo "=== Hysteria2 协议配置（优化版 VMess） ===" >> $output_file
			vmess_config='{"v":"2","ps":"'$isp_info'_Hysteria2_TLS","add":"'$domain'","port":"443","id":"'$uuid'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$domain'","path":"'$urlpath'","tls":"tls","sni":"'$domain'"}'
			echo "vmess://$(echo $vmess_config | base64 -w 0)" >> $output_file
			echo "" >> $output_file
			echo "注意：为兼容 Cloudflare Tunnel，使用 VMess 协议传输" >> $output_file
			;;
		4)
			# TUIC 配置（实际使用 VLESS）
			echo "=== TUIC v5 协议配置（优化版 VLESS） ===" >> $output_file
			echo "vless://$uuid@$domain:443?encryption=none&security=tls&type=ws&host=$domain&path=$urlpath&sni=$domain#${isp_info}_TUIC" >> $output_file
			echo "" >> $output_file
			echo "注意：为兼容 Cloudflare Tunnel，使用 VLESS 协议传输" >> $output_file
			;;
	esac
	
	echo "" >> $output_file
	echo "注意事项：" >> $output_file
	echo "1. 域名可替换为 Cloudflare 优选 IP" >> $output_file
	echo "2. 建议使用支持 sing-box 的客户端" >> $output_file
	echo "3. 如果连接失败，请检查域名是否可访问" >> $output_file
	echo "4. 查看详细日志: ./sing-box run -c config.json" >> $output_file
}

# 获取协议名称函数
function get_protocol_name(){
	case "$1" in
		1) echo "VMess" ;;
		2) echo "VLESS" ;;
		3) echo "Hysteria2" ;;
		4) echo "TUIC v5" ;;
		*) echo "Unknown" ;;
	esac
}

# 安装服务模式函数 (持久模式)
function installtunnel(){
	echo "=== 启动安装服务模式 ==="
	
	# 检查网络连通性
	if ! check_network; then
		read -p "网络连接异常，是否继续？(y/N): " continue_anyway
		if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
			echo "已取消操作"
			exit 1
		fi
	fi
	
	# 创建主目录
	mkdir -p /opt/singbox/ >/dev/null 2>&1
	
	# 清理旧文件
	rm -rf sing-box cloudflared-linux sing-box.tar.gz
	
	# 根据系统架构下载
	arch=$(uname -m)
	echo "检测到系统架构: $arch"
	
	case "$arch" in
		x86_64 | x64 | amd64 )
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-amd64.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" "cloudflared-linux" || exit 1
			;;
		i386 | i686 )
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-386.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386" "cloudflared-linux" || exit 1
			;;
		armv8 | arm64 | aarch64 )
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-arm64.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" "cloudflared-linux" || exit 1
			;;
		armv7l | armv7 )
			download_with_retry "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-armv7.tar.gz" "sing-box.tar.gz" || exit 1
			download_with_retry "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm" "cloudflared-linux" || exit 1
			;;
		* )
			echo "错误: 当前架构 $arch 不支持"
			exit 1
			;;
	esac
	
	# 解压和移动文件
	echo "解压程序文件..."
	
	# 验证和解压 tar.gz 文件
	if ! tar -tzf sing-box.tar.gz >/dev/null 2>&1; then
		echo "错误: sing-box.tar.gz 文件损坏或格式错误"
		exit 1
	fi
	
	if tar -xzf sing-box.tar.gz; then
		echo "✓ sing-box.tar.gz 解压成功"
	else
		echo "错误: 解压 sing-box.tar.gz 失败"
		exit 1
	fi
	
	# 移动文件到目标目录
	sing_box_binary=$(find . -name "sing-box" -type f 2>/dev/null | head -1)
	if [ -z "$sing_box_binary" ]; then
		echo "错误: 未找到 sing-box 可执行文件"
		exit 1
	fi
	
	mv "$sing_box_binary" /opt/singbox/
	mv cloudflared-linux /opt/singbox/
	chmod +x /opt/singbox/sing-box /opt/singbox/cloudflared-linux
	rm -rf sing-box.tar.gz sing-box-*
	
	# 生成配置参数
	uuid=$(cat /proc/sys/kernel/random/uuid)
	urlpath="/$(echo $uuid | awk -F- '{print $1}')"
	port=$((RANDOM + 10000))
	
	# 生成服务配置文件
	generate_service_config "$protocol" "$uuid" "$urlpath" "$port"
	
	# Cloudflare 认证流程
	clear
	echo "=== Cloudflare 域名授权 ==="
	echo "即将打开浏览器进行域名授权"
	echo "请在浏览器中完成域名绑定后继续"
	echo ""
	read -p "按回车键继续..."
	
	/opt/singbox/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel login
	
	clear
	
	# 获取域名
	while true; do
		read -p "输入完整的二级域名 (例如: proxy.example.com): " domain
		
		if [ -z "$domain" ]; then
			echo "错误: 域名不能为空"
			continue
		elif [ $(echo $domain | grep "\\.") ]; then
			break
		else
			echo "错误: 域名格式不正确，必须包含点号"
			continue
		fi
	done
	
	# 设置隧道
	tunnel_name=$(echo $domain | awk -F\\. '{print $1}')
	setup_tunnel "$tunnel_name" "$domain" "$port"
	
	# 创建系统服务
	create_system_service "$tunnel_name" "$current_os"
	
	# 生成客户端配置
	generate_client_config "$domain" "$uuid" "$urlpath" "$protocol" "/opt/singbox/client-config.txt"
	
	clear
	cat /opt/singbox/client-config.txt
	echo ""
	echo "服务安装完成！管理命令: singbox"
}

# 生成服务配置文件函数
function generate_service_config(){
	local protocol=$1
	local uuid=$2
	local urlpath=$3
	local port=$4
	
	case "$protocol" in
		1|2)
			# VMess/VLESS 配置
			local proto_name=$([ "$protocol" == "1" ] && echo "vmess" || echo "vless")
			cat > /opt/singbox/config.json << EOF
{
	"log": {
		"level": "info",
		"output": "/opt/singbox/singbox.log"
	},
	"inbounds": [{
		"type": "$proto_name",
		"tag": "${proto_name}-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "uuid": "$uuid"$([ "$protocol" == "1" ] && echo ', "alterId": 0') }],
		"transport": {
			"type": "ws",
			"path": "$urlpath",
			"headers": { "Host": "localhost" }
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
		3)
			# Hysteria2 配置
			cat > /opt/singbox/config.json << EOF
{
	"log": {
		"level": "info",
		"output": "/opt/singbox/singbox.log"
	},
	"inbounds": [{
		"type": "hysteria2",
		"tag": "hy2-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "password": "$uuid" }],
		"tls": {
			"enabled": true,
			"server_name": "localhost",
			"insecure": true
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
		4)
			# TUIC 配置
			short_id=$(echo $uuid | cut -c1-8)
			cat > /opt/singbox/config.json << EOF
{
	"log": {
		"level": "info",
		"output": "/opt/singbox/singbox.log"
	},
	"inbounds": [{
		"type": "tuic",
		"tag": "tuic-in",
		"listen": "127.0.0.1",
		"listen_port": $port,
		"users": [{ "uuid": "$uuid", "password": "$short_id" }],
		"congestion_control": "bbr",
		"tls": {
			"enabled": true,
			"server_name": "localhost",
			"insecure": true
		}
	}],
	"outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
			;;
	esac
}

# 设置隧道函数
function setup_tunnel(){
	local tunnel_name=$1
	local domain=$2
	local port=$3
	
	# 创建隧道
	echo "创建隧道: $tunnel_name"
	/opt/singbox/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel create $tunnel_name >tunnel.log 2>&1
	
	# 绑定域名
	echo "绑定域名: $domain"
	/opt/singbox/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel route dns --overwrite-dns $tunnel_name $domain >tunnel.log 2>&1
	
	# 获取隧道UUID
	tunnel_uuid=$(grep -o '[a-f0-9-]\{36\}' tunnel.log | head -1)
	echo "隧道UUID: $tunnel_uuid"
	
	# 创建 Cloudflare 配置文件
	cat > /opt/singbox/cloudflared.yaml << EOF
tunnel: $tunnel_uuid
credentials-file: /root/.cloudflared/$tunnel_uuid.json

ingress:
  - hostname: $domain
    service: http://127.0.0.1:$port
  - service: http_status:404
EOF
	
	rm -f tunnel.log
}

# 创建系统服务函数
function create_system_service(){
	local tunnel_name=$1
	local os_type=$2
	
	if [ "$os_type" == "Alpine" ]; then
		# Alpine 系统使用 OpenRC
		cat > /etc/local.d/singbox.start << EOF
/opt/singbox/sing-box run -c /opt/singbox/config.json &
EOF
		cat > /etc/local.d/cloudflared.start << EOF
/opt/singbox/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/singbox/cloudflared.yaml run $tunnel_name &
EOF
		chmod +x /etc/local.d/singbox.start /etc/local.d/cloudflared.start
		rc-update add local
		/etc/local.d/singbox.start >/dev/null 2>&1
		/etc/local.d/cloudflared.start >/dev/null 2>&1
	else
		# 其他系统使用 systemd
		cat > /lib/systemd/system/singbox.service << EOF
[Unit]
Description=sing-box
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/singbox/sing-box run -c /opt/singbox/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

		cat > /lib/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/singbox/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/singbox/cloudflared.yaml run $tunnel_name
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

		systemctl enable singbox.service cloudflared.service >/dev/null 2>&1
		systemctl daemon-reload
		systemctl start singbox.service cloudflared.service
	fi
	
	# 创建管理脚本
	create_management_script "$tunnel_name" "$os_type"
}

# 创建管理脚本函数
function create_management_script(){
	local tunnel_name=$1
	local os_type=$2
	
	cat > /opt/singbox/singbox.sh << 'EOF'
#!/bin/bash
while true; do
	clear
	if [ "$1" == "Alpine" ]; then
		if [ $(ps -ef | grep sing-box | grep -v grep | wc -l) == 0 ]; then
			singbox_status="已停止"
		else
			singbox_status="运行中"
		fi
		if [ $(ps -ef | grep cloudflared-linux | grep -v grep | wc -l) == 0 ]; then
			cloudflared_status="已停止"
		else
			cloudflared_status="运行中"
		fi
	else
		singbox_status=$(systemctl is-active singbox.service)
		cloudflared_status=$(systemctl is-active cloudflared.service)
	fi
	
	echo "=== Sing-box 服务管理 ==="
	echo "Sing-box: $singbox_status"
	echo "Cloudflared: $cloudflared_status"
	echo ""
	echo "1. 启动服务"
	echo "2. 停止服务"
	echo "3. 重启服务"
	echo "4. 查看配置"
	echo "5. 查看日志"
	echo "6. 卸载服务"
	echo "0. 退出"
	echo ""
	read -p "请选择操作 (默认0): " choice
	
	case "${choice:-0}" in
		1)
			if [ "$1" == "Alpine" ]; then
				/etc/local.d/singbox.start >/dev/null 2>&1
				/etc/local.d/cloudflared.start >/dev/null 2>&1
			else
				systemctl start singbox.service cloudflared.service
			fi
			echo "服务已启动"
			sleep 2
			;;
		2)
			if [ "$1" == "Alpine" ]; then
				kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
				kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			else
				systemctl stop singbox.service cloudflared.service
			fi
			echo "服务已停止"
			sleep 2
			;;
		3)
			if [ "$1" == "Alpine" ]; then
				kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
				kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
				sleep 1
				/etc/local.d/singbox.start >/dev/null 2>&1
				/etc/local.d/cloudflared.start >/dev/null 2>&1
			else
				systemctl restart singbox.service cloudflared.service
			fi
			echo "服务已重启"
			sleep 2
			;;
		4)
			clear
			cat /opt/singbox/client-config.txt
			echo ""
			read -p "按回车键继续..."
			;;
		5)
			clear
			echo "=== Sing-box 日志 ==="
			tail -20 /opt/singbox/singbox.log 2>/dev/null || echo "日志文件不存在"
			echo ""
			read -p "按回车键继续..."
			;;
		6)
			read -p "确定要卸载服务吗？(y/N): " confirm
			if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
				if [ "$1" == "Alpine" ]; then
					kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
					kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
					rm -rf /etc/local.d/singbox.start /etc/local.d/cloudflared.start
				else
					systemctl stop singbox.service cloudflared.service
					systemctl disable singbox.service cloudflared.service
					rm -rf /lib/systemd/system/singbox.service /lib/systemd/system/cloudflared.service
					systemctl daemon-reload
				fi
				rm -rf /opt/singbox /usr/bin/singbox ~/.cloudflared
				echo "服务已完全卸载"
				echo "如需彻底删除授权记录，请访问:"
				echo "https://dash.cloudflare.com/profile/api-tokens"
				exit
			fi
			;;
		0)
			exit
			;;
		*)
			echo "无效选择"
			sleep 1
			;;
	esac
done
EOF
	
	chmod +x /opt/singbox/singbox.sh
	ln -sf /opt/singbox/singbox.sh /usr/bin/singbox
}

# 主程序开始
clear
echo "==================================================="
echo "    Sing-box + Cloudflare Argo 一键部署脚本"
echo "==================================================="
echo ""
echo "梅哈模式: 不需要自己提供域名，使用 CF ARGO QUICK TUNNEL"
echo "梅哈模式在重启或者脚本再次运行后失效"
echo ""
echo "安装服务模式: 需要有 CF 托管域名，需要手动绑定 ARGO 服务"
echo "首次绑定 ARGO 服务后，可拷贝 /root/.cloudflared 目录到新系统"
echo ""
echo "Sing-box 是一个通用的代理平台！"
echo ""
echo "1. 梅哈模式 (临时)"
echo "2. 安装服务 (永久)"
echo "3. 卸载服务"
echo "4. 清空缓存"
echo "5. 故障排除"
echo "0. 退出脚本"
echo ""
read -p "请选择模式 (默认1): " mode

# 默认选择梅哈模式
mode=${mode:-1}

case "$mode" in
	1)
		# 梅哈模式
		echo ""
		echo "=== 协议选择 ==="
		echo "1. VMess (传统协议，兼容性好)"
		echo "2. VLESS (轻量级协议，性能更好)"
		echo "3. Hysteria2 (新一代协议，适合高延迟网络)"
		echo "4. TUIC v5 (基于QUIC的协议，适合移动网络)"
		read -p "请选择协议 (默认1): " protocol
		protocol=${protocol:-1}
		
		if [[ ! "$protocol" =~ ^[1-4]$ ]]; then
			echo "错误: 请输入正确的协议编号 (1-4)"
			exit 1
		fi
		
		echo ""
		read -p "请选择 Argo 连接模式 (4=IPv4, 6=IPv6, 默认4): " ips
		ips=${ips:-4}
		
		if [[ ! "$ips" =~ ^[46]$ ]]; then
			echo "错误: 请输入 4 或 6"
			exit 1
		fi
		
		# 停止旧进程
		echo "清理旧进程..."
		if [ "$current_os" == "Alpine" ]; then
			kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
		else
			kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $2}') >/dev/null 2>&1
			kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
		fi
		
		rm -rf sing-box cloudflared-linux client-config.txt config.json
		quicktunnel
		;;
		
	2)
		# 安装服务模式
		echo ""
		echo "=== 协议选择 ==="
		echo "1. VMess (传统协议，兼容性好)"
		echo "2. VLESS (轻量级协议，性能更好)"
		echo "3. Hysteria2 (新一代协议，适合高延迟网络)"
		echo "4. TUIC v5 (基于QUIC的协议，适合移动网络)"
		read -p "请选择协议 (默认1): " protocol
		protocol=${protocol:-1}
		
		if [[ ! "$protocol" =~ ^[1-4]$ ]]; then
			echo "错误: 请输入正确的协议编号 (1-4)"
			exit 1
		fi
		
		echo ""
		read -p "请选择 Argo 连接模式 (4=IPv4, 6=IPv6, 默认4): " ips
		ips=${ips:-4}
		
		if [[ ! "$ips" =~ ^[46]$ ]]; then
			echo "错误: 请输入 4 或 6"
			exit 1
		fi
		
		# 停止旧服务
		echo "清理旧服务..."
		if [ "$current_os" == "Alpine" ]; then
			kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			rm -rf /etc/local.d/singbox.start /etc/local.d/cloudflared.start
		else
			systemctl stop singbox.service cloudflared.service >/dev/null 2>&1
			systemctl disable singbox.service cloudflared.service >/dev/null 2>&1
			rm -rf /lib/systemd/system/singbox.service /lib/systemd/system/cloudflared.service
			systemctl daemon-reload >/dev/null 2>&1
		fi
		
		rm -rf /opt/singbox /usr/bin/singbox
		installtunnel
		;;
		
	3)
		# 卸载服务
		echo "正在卸载服务..."
		if [ "$current_os" == "Alpine" ]; then
			kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			rm -rf /etc/local.d/singbox.start /etc/local.d/cloudflared.start
		else
			systemctl stop singbox.service cloudflared.service >/dev/null 2>&1
			systemctl disable singbox.service cloudflared.service >/dev/null 2>&1
			rm -rf /lib/systemd/system/singbox.service /lib/systemd/system/cloudflared.service
			systemctl daemon-reload >/dev/null 2>&1
		fi
		
		rm -rf /opt/singbox /usr/bin/singbox ~/.cloudflared
		
		echo "所有服务已卸载完成！"
		echo ""
		echo "如需彻底删除授权记录，请访问:"
		echo "https://dash.cloudflare.com/profile/api-tokens"
		echo "删除授权的 Argo Tunnel API Token"
		;;
		
	4)
		# 清空缓存
		echo "正在清理缓存文件..."
		if [ "$current_os" == "Alpine" ]; then
			kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $1}') >/dev/null 2>&1
			kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
		else
			kill -9 $(ps -ef | grep sing-box | grep -v grep | awk '{print $2}') >/dev/null 2>&1
			kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
		fi
		
		rm -rf sing-box cloudflared-linux client-config.txt config.json argo.log tunnel.log sing-box.tar.gz
		echo "缓存清理完成！"
		;;
		
	5)
		# 故障排除
		echo "正在运行故障排除工具..."
		echo ""
		
		# 检查进程状态
		echo "=== 进程状态检查 ==="
		if ps aux | grep -v grep | grep sing-box >/dev/null; then
			echo "✓ sing-box 进程运行中"
		else
			echo "✗ sing-box 进程未运行"
		fi
		
		if ps aux | grep -v grep | grep cloudflared >/dev/null; then
			echo "✓ cloudflared 进程运行中"
		else
			echo "✗ cloudflared 进程未运行"
		fi
		echo ""
		
		# 检查配置文件
		echo "=== 配置文件检查 ==="
		if [ -f "config.json" ]; then
			echo "✓ 发现 config.json"
			if [ -f "./sing-box" ]; then
				echo "验证配置文件:"
				./sing-box check -c config.json
			fi
		else
			echo "✗ config.json 不存在"
		fi
		
		if [ -f "client-config.txt" ]; then
			echo "✓ 发现 client-config.txt"
			echo "客户端配置:"
			cat client-config.txt
		else
			echo "✗ client-config.txt 不存在"
		fi
		echo ""
		
		# 网络连通性测试
		echo "=== 网络连通性测试 ==="
		if curl -s --max-time 5 https://1.1.1.1 >/dev/null; then
			echo "✓ 网络连接正常"
		else
			echo "✗ 网络连接异常"
		fi
		echo ""
		
		echo "=== 修复建议 ==="
		echo "1. 重新运行脚本: bash singbox-deploy.sh"
		echo "2. 手动测试: ./sing-box run -c config.json"
		echo "3. 查看详细日志: ./sing-box run -c config.json -D"
		echo "4. 检查防火墙设置"
		echo "5. 尝试更换协议或端口"
		echo ""
		read -p "按回车键继续..."
		;;
		
	0)
		echo "退出成功！"
		exit 0
		;;
		
	*)
		echo "错误: 无效的选择，请输入 0-5"
		exit 1
		;;
esac
