#!/bin/bash

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# 清屏函数
clear_screen() {
    clear
}

# 显示欢迎信息
show_welcome() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${GREEN}    欢迎使用交互式脚本工具！    ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

# 显示菜单
show_menu() {
    echo -e "${YELLOW}请选择要执行的操作：${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} 显示系统信息"
    echo -e "${GREEN}2.${NC} 安装Acme申请SSL证书"
    echo -e "${GREEN}3.${NC} 显示当前进程"
    echo -e "${GREEN}4.${NC} 网络连接状态"
    echo -e "${GREEN}5.${NC} 创建备份目录"
    echo -e "${RED}0.${NC} 退出程序"
    echo ""
    echo -n -e "${BLUE}请输入选项 [0-5]: ${NC}"
}

# 任务1: 显示系统信息
task_system_info() {
    echo -e "\n${YELLOW}=== 系统信息 ===${NC}"
    echo -e "${GREEN}操作系统:${NC} $(uname -s)"
    echo -e "${GREEN}内核版本:${NC} $(uname -r)"
    echo -e "${GREEN}主机名:${NC} $(hostname)"
    echo -e "${GREEN}当前用户:${NC} $(whoami)"
    echo -e "${GREEN}系统时间:${NC} $(date)"
    echo -e "${GREEN}系统运行时间:${NC} $(uptime -p 2>/dev/null || uptime)"
}

# 任务2: 安装Acme申请证书
task_acme_ssl() {
    echo -e "\n${YELLOW}=== Acme SSL证书申请 ===${NC}"
    
    # 获取域名输入
    echo -n -e "${BLUE}请输入域名 (例如: aa.com): ${NC}"
    read domain
    
    # 验证域名格式（支持多级域名）
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}域名格式无效！请输入有效的域名（支持多级域名，如：aa.bb.com）${NC}"
        return 1
    fi
    
    # 端口配置
    echo -n -e "${BLUE}请输入后端服务端口 (默认80，直接回车使用默认): ${NC}"
    read backend_port
    
    # 如果用户直接回车，使用默认端口80
    if [[ -z "$backend_port" ]]; then
        backend_port=80
        echo -e "${GREEN}使用默认端口: $backend_port${NC}"
    else
        # 验证端口格式
        if [[ ! "$backend_port" =~ ^[0-9]+$ ]] || [ "$backend_port" -lt 1 ] || [ "$backend_port" -gt 65535 ]; then
            echo -e "${RED}端口格式无效！请输入1-65535之间的数字${NC}"
            return 1
        fi
        echo -e "${GREEN}使用自定义端口: $backend_port${NC}"
    fi
    
    echo -e "\n${GREEN}开始为域名 $domain 申请SSL证书...${NC}"
    
    # 检查域名是否已存在于证书列表中
    echo -e "\n${YELLOW}1. 检查域名证书状态...${NC}"
    if [ -f ~/.acme.sh/acme.sh ]; then
        cert_list=$(~/.acme.sh/acme.sh --list 2>/dev/null)
        if echo "$cert_list" | grep -q "$domain"; then
            echo -e "${YELLOW}发现域名 $domain 已存在证书！${NC}"
            echo -e "${BLUE}当前证书信息：${NC}"
            ~/.acme.sh/acme.sh --list | grep -A 2 -B 1 "$domain"
            
            echo -n -e "\n${PURPLE}是否要重新申请证书？[y/N]: ${NC}"
            read renew_choice
            case ${renew_choice,,} in
                y|yes)
                    echo -e "${GREEN}将重新申请证书...${NC}"
                    ;;
                *)
                    echo -e "${BLUE}跳过证书申请，使用现有证书${NC}"
                    return 0
                    ;;
            esac
        else
            echo -e "${GREEN}域名 $domain 未找到现有证书，将申请新证书${NC}"
        fi
    else
        echo -e "${GREEN}acme.sh未安装，将进行全新安装和证书申请${NC}"
    fi
    
    # 检查并安装socat
    echo -e "\n${YELLOW}2. 检查socat...${NC}"
    if ! command -v socat &> /dev/null; then
        echo -e "${YELLOW}socat未安装，正在安装...${NC}"
        apt update && apt install -y socat
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}socat安装成功${NC}"
        else
            echo -e "${RED}socat安装失败${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}socat已安装${NC}"
    fi
    
    # 检查并安装acme.sh
    echo -e "\n${YELLOW}3. 检查acme.sh...${NC}"
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        echo -e "${YELLOW}acme.sh未安装，正在安装...${NC}"
        curl -s https://get.acme.sh | sh -s email=caikaibai@outlook.com
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}acme.sh安装成功${NC}"
        else
            echo -e "${RED}acme.sh安装失败${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}acme.sh已安装${NC}"
    fi
    
    # 设置alias
    echo -e "\n${YELLOW}4. 设置acme.sh alias...${NC}"
    alias acme.sh=~/.acme.sh/acme.sh
    echo -e "${GREEN}alias设置完成${NC}"
    
    # 创建nginx配置文件
    echo -e "\n${YELLOW}5. 创建nginx配置文件...${NC}"
    nginx_conf="/etc/nginx/conf.d/${domain}.conf"
    mkdir -p /etc/nginx/conf.d
    mkdir -p /www/logs
    
    # 创建域名去点版本用于文件名
    domain_clean=$(echo "$domain" | sed 's/\.//g')
    
    if [ "$backend_port" -eq 80 ]; then
        # 默认80端口配置（用于证书申请验证）
        cat > "$nginx_conf" << EOF
server {
    listen 80;
    server_name $domain www.$domain;
    
    location / {
        return 200 'Hello World';
        add_header Content-Type text/plain;
    }
}
EOF
    else
        # 自定义端口的完整SSL配置（先创建HTTP版本用于证书申请）
        cat > "$nginx_conf" << EOF
server {
    listen 80;
    server_name $domain www.$domain;
    
    location / {
        return 200 'Hello World';
        add_header Content-Type text/plain;
    }
}
EOF
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}nginx配置文件创建成功: $nginx_conf${NC}"
    else
        echo -e "${RED}nginx配置文件创建失败${NC}"
        return 1
    fi
    
    # 重启nginx
    echo -e "\n${YELLOW}6. 重启nginx...${NC}"
    systemctl restart nginx
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}nginx重启成功${NC}"
    else
        echo -e "${RED}nginx重启失败，请检查配置${NC}"
        return 1
    fi
    
    # 申请证书
    echo -e "\n${YELLOW}7. 申请SSL证书...${NC}"
    ~/.acme.sh/acme.sh --issue -d $domain --nginx --force
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SSL证书申请成功${NC}"
    else
        echo -e "${RED}SSL证书申请失败${NC}"
        return 1
    fi
    
    # 创建证书目录
    echo -e "\n${YELLOW}8. 安装SSL证书...${NC}"
    mkdir -p /root/cert
    
    # 安装证书
    ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
        --key-file /root/cert/${domain}.key \
        --fullchain-file /root/cert/${domain}.crt
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SSL证书安装成功${NC}"
        echo -e "${GREEN}证书路径:${NC}"
        echo -e "  私钥: /root/cert/${domain}.key"
        echo -e "  证书: /root/cert/${domain}.crt"
    else
        echo -e "${RED}SSL证书安装失败${NC}"
        return 1
    fi
    
    # 设置自动更新
    echo -e "\n${YELLOW}9. 设置自动更新...${NC}"
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}自动更新设置成功${NC}"
    else
        echo -e "${YELLOW}自动更新设置失败，但不影响证书使用${NC}"
    fi
    
    # 显示证书列表
    echo -e "\n${YELLOW}10. 当前证书列表:${NC}"
    ~/.acme.sh/acme.sh --list
    
    # 如果是自定义端口，更新nginx配置为SSL反向代理
    if [ "$backend_port" -ne 80 ]; then
        echo -e "\n${YELLOW}11. 更新nginx配置为SSL反向代理...${NC}"
        
        cat > "$nginx_conf" << EOF
server {
    listen 80;
    server_name $domain www.$domain;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain www.$domain;
    ssl_certificate    /root/cert/${domain}.crt;
    ssl_certificate_key    /root/cert/${domain}.key;
    
    # SSL配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    ssl_prefer_server_ciphers on;
    
    location / {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Range \$http_range;
        proxy_set_header If-Range \$http_if_range;
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$backend_port;
        # the max size of file to upload
        client_max_body_size 20000m;
    }
    access_log  /www/logs/${domain_clean}.log;
}
EOF
        
        # 重新加载nginx配置
        systemctl reload nginx
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}nginx SSL反向代理配置更新成功${NC}"
        else
            echo -e "${RED}nginx配置更新失败，请检查配置${NC}"
            return 1
        fi
    fi
    
    echo -e "\n${GREEN}=== SSL证书申请完成 ===${NC}"
    if [ "$backend_port" -ne 80 ]; then
        echo -e "${BLUE}已配置SSL反向代理到本地端口: $backend_port${NC}"
        echo -e "${BLUE}HTTP访问将自动重定向到HTTPS${NC}"
        echo -e "${BLUE}日志文件: /www/logs/${domain_clean}.log${NC}"
    else
        echo -e "${BLUE}提示: 请手动更新nginx配置以使用SSL证书${NC}"
    fi
}

# 任务3: 显示当前进程
task_processes() {
    echo -e "\n${YELLOW}=== 当前运行的进程 (前10个) ===${NC}"
    ps aux --sort=-%cpu | head -11
}

# 任务4: 网络连接状态
task_network() {
    echo -e "\n${YELLOW}=== 网络连接状态 ===${NC}"
    echo -e "${GREEN}网络接口信息:${NC}"
    ip addr show 2>/dev/null || ifconfig
    echo -e "\n${GREEN}活动连接:${NC}"
    netstat -tuln 2>/dev/null | head -10 || ss -tuln | head -10
}

# 任务5: 创建备份目录
task_backup() {
    echo -e "\n${YELLOW}=== 创建备份目录 ===${NC}"
    backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}成功创建备份目录: $backup_dir${NC}"
        echo -e "${GREEN}目录路径: $(pwd)/$backup_dir${NC}"
    else
        echo -e "${RED}创建备份目录失败！${NC}"
    fi
}

# 暂停函数
pause() {
    echo ""
    echo -n -e "${BLUE}按回车键继续...${NC}"
    read
}

# 主循环
main() {
    while true; do
        clear_screen
        show_welcome
        show_menu
        
        read choice
        
        case $choice in
            1)
                task_system_info
                pause
                ;;
            2)
                task_acme_ssl
                pause
                ;;
            3)
                task_processes
                pause
                ;;
            4)
                task_network
                pause
                ;;
            5)
                task_backup
                pause
                ;;
            0)
                echo -e "\n${GREEN}谢谢使用，再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "\n${RED}无效选项，请输入 0-5 之间的数字！${NC}"
                sleep 2
                ;;
        esac
    done
}

# 运行主程序
main
