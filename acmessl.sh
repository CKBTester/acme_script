#!/bin/bash

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

ACME_SH="$HOME/.acme.sh/acme.sh"

# 发行版识别与包管理
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "dnf -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "dnf -y install")

SYSTEM=""
PM_IDX=-1

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}请以 root 身份运行本脚本${NC}"
    exit 1
  fi
}

detect_system() {
  local CMD
  CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" \
       "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" \
       "$(lsb_release -sd 2>/dev/null)" \
       "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" \
       "$(grep . /etc/redhat-release 2>/dev/null)" \
       "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")
  local SYS
  for i in "${CMD[@]}"; do
    SYS="$i"
    [[ -n $SYS ]] && break
  done
  for ((int=0; int<${#REGEX[@]}; int++)); do
    if [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]]; then
      SYSTEM="${RELEASE[int]}"; PM_IDX=$int; break
    fi
  done
  if [[ -z $SYSTEM ]]; then
    echo -e "${RED}不支持当前系统，请使用主流发行版${NC}"; exit 1
  fi
}

pkg_update() { eval "${PACKAGE_UPDATE[PM_IDX]}"; }
pkg_install() { eval "${PACKAGE_INSTALL[PM_IDX]} $*"; }

ensure_dependencies() {
  # curl wget socat openssl lsof dig cron
  if ! command -v curl >/dev/null 2>&1; then pkg_update; pkg_install curl; fi
  if ! command -v wget >/dev/null 2>&1; then pkg_install wget; fi
  if ! command -v socat >/dev/null 2>&1; then pkg_install socat; fi
  if ! command -v openssl >/dev/null 2>&1; then pkg_install openssl; fi
  if ! command -v lsof >/dev/null 2>&1; then pkg_install lsof; fi
  if ! command -v dig >/dev/null 2>&1; then
    # 兼容 Debian/Ubuntu 与 RHEL 系
    pkg_install dnsutils || pkg_install bind-utils || true
  fi
  # cron
  if [[ $SYSTEM == "CentOS" ]]; then
    pkg_install cronie || true
    systemctl enable crond >/dev/null 2>&1 || true
    systemctl start crond >/dev/null 2>&1 || true
  else
    pkg_install cron || true
    systemctl enable cron >/dev/null 2>&1 || true
    systemctl start cron >/dev/null 2>&1 || true
  fi
}

check_nginx() {
  if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${YELLOW}未检测到 nginx，开始安装...${NC}"
    pkg_update; pkg_install nginx || { echo -e "${RED}nginx 安装失败，请手动安装后重试${NC}"; return 1; }
  fi
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl start nginx >/dev/null 2>&1 || true
  return 0
}

check_port_in_use() {
  local port=$1
  if lsof -i:"$port" | grep -iq "listen"; then
    return 0
  else
    return 1
  fi
}

get_public_ip() {
  local ipv4 ipv6
  ipv4=$(curl -s4m8 ip.sb -k | sed -n 1p)
  ipv6=$(curl -s6m8 ip.sb -k | sed -n 1p)
  [[ -n $ipv4 ]] && echo "$ipv4" && return 0
  [[ -n $ipv6 ]] && echo "$ipv6" && return 0
  echo ""
}

resolve_domain_ip() {
  local domain=$1
  local ip
  ip=$(dig @8.8.8.8 +time=2 +short "$domain" 2>/dev/null | sed -n 1p)
  if [[ -z $ip ]] || echo "$ip" | grep -q "network unreachable\|timed out"; then
    ip=$(dig @2001:4860:4860::8888 +time=2 aaaa +short "$domain" 2>/dev/null | sed -n 1p)
  fi
  echo "$ip"
}

install_acmesh() {
  if [[ -f $ACME_SH ]]; then
    echo -e "${GREEN}acme.sh 已安装：$($ACME_SH -v 2>/dev/null)${NC}"
    $ACME_SH --upgrade --auto-upgrade
    return 0
  fi
  echo -n -e "${BLUE}请输入注册邮箱 (回车将自动生成): ${NC}"; read email
  if [[ -z $email ]]; then
    local automail
    automail=$(date +%s%N | md5sum | cut -c 1-16)
    email="$automail@gmail.com"
    echo -e "${YELLOW}使用自动生成邮箱: ${email}${NC}"
  fi
  curl -s https://get.acme.sh | sh -s email=$email || { echo -e "${RED}acme.sh 安装失败${NC}"; return 1; }
  $ACME_SH --upgrade --auto-upgrade
  echo -e "${GREEN}acme.sh 安装完成：$($ACME_SH -v 2>/dev/null)${NC}"
}

uninstall_acmesh() {
  if [[ ! -f $ACME_SH ]]; then echo -e "${YELLOW}未安装 acme.sh${NC}"; return 0; fi
  $ACME_SH --uninstall
  rm -rf "$HOME/.acme.sh"
  echo -e "${GREEN}acme.sh 已卸载${NC}"
}

switch_ca() {
  if [[ ! -f $ACME_SH ]]; then echo -e "${YELLOW}未安装 acme.sh${NC}"; return 1; fi
  echo -e "${YELLOW}请选择证书颁发机构：${NC}"
  echo -e " ${GREEN}1.${NC} Let's Encrypt (默认)"
  echo -e " ${GREEN}2.${NC} BuyPass"
  echo -e " ${GREEN}3.${NC} ZeroSSL"
  echo -n -e "${BLUE}请输入选项 [1-3]: ${NC}"; read p
  case "$p" in
    2) $ACME_SH --set-default-ca --server buypass && echo -e "${GREEN}已切换为 BuyPass${NC}" ;;
    3) $ACME_SH --set-default-ca --server zerossl && echo -e "${GREEN}已切换为 ZeroSSL${NC}" ;;
    *) $ACME_SH --set-default-ca --server letsencrypt && echo -e "${GREEN}已切换为 Let's Encrypt${NC}" ;;
  esac
}

list_cert() { [[ -f $ACME_SH ]] && $ACME_SH --list || echo -e "${YELLOW}未安装 acme.sh${NC}"; }

revoke_cert() {
  if [[ ! -f $ACME_SH ]]; then echo -e "${YELLOW}未安装 acme.sh${NC}"; return 1; fi
  $ACME_SH --list
  echo -n -e "${BLUE}请输入要撤销的域名 (Main_Domain): ${NC}"; read domain
  [[ -z $domain ]] && echo -e "${RED}未输入域名${NC}" && return 1
  if $ACME_SH --list | grep -q "^$domain\b"; then
    $ACME_SH --revoke -d "$domain" --ecc 2>/dev/null
    $ACME_SH --remove -d "$domain" --ecc 2>/dev/null
    rm -rf "$HOME/.acme.sh/${domain}_ecc" 2>/dev/null
    rm -f "/root/cert/${domain}.crt" "/root/cert/${domain}.key" 2>/dev/null
    echo -e "${GREEN}已撤销并移除 ${domain} 的证书${NC}"
  else
    echo -e "${RED}未找到 ${domain} 的证书${NC}"
  fi
}

renew_cert() { [[ -f $ACME_SH ]] && $ACME_SH --cron -f || echo -e "${YELLOW}未安装 acme.sh${NC}"; }

# ================= acme + nginx 申请（增强版） =================
issue_via_nginx() {
  local domain=$1
  local include_www=$2   # yes/no
  local force_flag=$3    # --force 或空

  check_nginx || return 1

  mkdir -p /etc/nginx/conf.d /www/logs /root/cert

  local nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  local domain_clean
  domain_clean=$(echo "$domain" | sed 's/\.//g')

  # 基础 HTTP 配置，便于 --nginx 验证
  cat > "$nginx_conf" <<EOF
server {
    listen 80;
    server_name $domain ${include_www:+www.$domain};
    location / {
        return 200 'Hello World';
        add_header Content-Type text/plain;
    }
}
EOF

  systemctl restart nginx || { echo -e "${RED}nginx 重启失败，请检查配置${NC}"; return 1; }

  # 选择域名集合
  local domains=(-d "$domain")
  if [[ $include_www == "yes" ]]; then
    domains+=(-d "www.$domain")
  fi

  echo -e "${YELLOW}开始通过 nginx 验证申请证书...${NC}"
  $ACME_SH --issue "${domains[@]}" --nginx -k ec-256 $force_flag || { echo -e "${RED}证书申请失败${NC}"; return 1; }

  # 安装证书到 /root/cert
  $ACME_SH --install-cert -d "$domain" --ecc \
    --key-file "/root/cert/${domain}.key" \
    --fullchain-file "/root/cert/${domain}.crt" || { echo -e "${RED}证书安装失败${NC}"; return 1; }

  echo -e "${GREEN}证书申请与安装完成${NC}"
  echo -e "  私钥: /root/cert/${domain}.key"
  echo -e "  证书: /root/cert/${domain}.crt"

  # 自动升级/续期
  $ACME_SH --upgrade --auto-upgrade >/dev/null 2>&1 || true
}

# ================= Cloudflare DNS 模式 =================
issue_cf_tld() {
  if [[ ! -f $ACME_SH ]]; then echo -e "${YELLOW}未安装 acme.sh，将先安装${NC}"; install_acmesh || return 1; fi
  echo -n -e "${BLUE}请输入需要申请证书的域名: ${NC}"; read domain
  [[ -z $domain ]] && echo -e "${RED}未输入域名${NC}" && return 1
  if [[ ${domain: -2} =~ ^(cf|ga|gq|ml|tk)$ ]]; then
    echo -e "${RED}Freenom 免费域名不支持 Cloudflare API${NC}"; return 1
  fi
  echo -n -e "${BLUE}请输入 Cloudflare Global API Key: ${NC}"; read cfgak
  [[ -z $cfgak ]] && echo -e "${RED}未输入 API Key${NC}" && return 1
  echo -n -e "${BLUE}请输入 Cloudflare 登录邮箱: ${NC}"; read cfemail
  [[ -z $cfemail ]] && echo -e "${RED}未输入邮箱${NC}" && return 1
  export CF_Key="$cfgak"; export CF_Email="$cfemail"
  $ACME_SH --issue --dns dns_cf -d "$domain" -k ec-256 || { echo -e "${RED}证书申请失败${NC}"; return 1; }
  mkdir -p /root/cert
  $ACME_SH --install-cert -d "$domain" --ecc \
    --key-file "/root/cert/${domain}.key" \
    --fullchain-file "/root/cert/${domain}.crt" || { echo -e "${RED}证书安装失败${NC}"; return 1; }
  echo -e "${GREEN}已安装到 /root/cert/${domain}.crt /root/cert/${domain}.key${NC}"
}

issue_cf_wildcard() {
  if [[ ! -f $ACME_SH ]]; then echo -e "${YELLOW}未安装 acme.sh，将先安装${NC}"; install_acmesh || return 1; fi
  echo -n -e "${BLUE}请输入需要申请证书的根域 (例如: example.com): ${NC}"; read domain
  [[ -z $domain ]] && echo -e "${RED}未输入域名${NC}" && return 1
  if [[ ${domain: -2} =~ ^(cf|ga|gq|ml|tk)$ ]]; then
    echo -e "${RED}Freenom 免费域名不支持 Cloudflare API${NC}"; return 1
  fi
  echo -n -e "${BLUE}请输入 Cloudflare Global API Key: ${NC}"; read cfgak
  [[ -z $cfgak ]] && echo -e "${RED}未输入 API Key${NC}" && return 1
  echo -n -e "${BLUE}请输入 Cloudflare 登录邮箱: ${NC}"; read cfemail
  [[ -z $cfemail ]] && echo -e "${RED}未输入邮箱${NC}" && return 1
  export CF_Key="$cfgak"; export CF_Email="$cfemail"
  $ACME_SH --issue --dns dns_cf -d "*.${domain}" -d "$domain" -k ec-256 || { echo -e "${RED}证书申请失败${NC}"; return 1; }
  mkdir -p /root/cert
  # 以通配符为主域签发，需要用 "*.domain" 指定安装
  $ACME_SH --install-cert -d "*.${domain}" --ecc \
    --key-file "/root/cert/${domain}.key" \
    --fullchain-file "/root/cert/${domain}.crt" || { echo -e "${RED}证书安装失败${NC}"; return 1; }
  echo -e "${GREEN}已安装到 /root/cert/${domain}.crt /root/cert/${domain}.key${NC}"
}

# ================= 交互式 UI =================
clear_screen() { clear; }

show_welcome() {
  echo -e "${BLUE}================================${NC}"
  echo -e "${GREEN}   欢迎使用 Nginx/Acme 一体化工具   ${NC}"
  echo -e "${BLUE}================================${NC}"
  echo ""
}

show_menu() {
  echo -e "${YELLOW}请选择要执行的操作：${NC}"
  echo ""
  echo -e "${GREEN}1.${NC} 显示系统信息"
  echo -e "${GREEN}2.${NC} 使用 Nginx 快速申请/安装 SSL (支持自动反代)"
  echo -e "${GREEN}3.${NC} 显示当前进程"
  echo -e "${GREEN}4.${NC} 网络连接状态"
  echo -e "${GREEN}5.${NC} 创建备份目录"
  echo -e "${GREEN}6.${NC} 安装/升级 acme.sh"
  echo -e "${GREEN}7.${NC} 卸载 acme.sh"
  echo -e "${GREEN}8.${NC} CF API 申请单域名证书"
  echo -e "${GREEN}9.${NC} CF API 申请泛域名证书"
  echo -e "${GREEN}10.${NC} 查看已申请证书"
  echo -e "${GREEN}11.${NC} 撤销并删除证书"
  echo -e "${GREEN}12.${NC} 手动续期证书"
  echo -e "${GREEN}13.${NC} 切换证书颁发机构"
  echo -e "${RED}0.${NC} 退出程序"
  echo ""
  echo -n -e "${BLUE}请输入选项 [0-13]: ${NC}"
}

# 任务1: 系统信息
task_system_info() {
  echo -e "\n${YELLOW}=== 系统信息 ===${NC}"
  echo -e "${GREEN}系统: ${NC}${SYSTEM}"
  echo -e "${GREEN}内核: ${NC}$(uname -sr)"
  echo -e "${GREEN}主机名: ${NC}$(hostname)"
  echo -e "${GREEN}当前用户: ${NC}$(whoami)"
  echo -e "${GREEN}时间: ${NC}$(date)"
  echo -e "${GREEN}运行时长: ${NC}$(uptime -p 2>/dev/null || uptime)"
}

# 任务2: Nginx 一键申请/安装
task_acme_ssl() {
  echo -e "\n${YELLOW}=== 基于 Nginx 的 SSL 申请 ===${NC}"
  echo -n -e "${BLUE}请输入域名 (例如: aa.com): ${NC}"; read domain
  if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}域名格式无效${NC}"; return 1
  fi
  echo -n -e "${BLUE}请输入后端服务端口 (默认80，回车使用): ${NC}"; read backend_port
  if [[ -z $backend_port ]]; then backend_port=80; echo -e "${GREEN}使用默认端口: 80${NC}"; else
    if [[ ! $backend_port =~ ^[0-9]+$ ]] || [[ $backend_port -lt 1 || $backend_port -gt 65535 ]]; then
      echo -e "${RED}端口无效${NC}"; return 1; fi
  fi

  # 依赖与 acme.sh
  ensure_dependencies
  install_acmesh || return 1

  # 是否包含 www 申请
  local include_www="yes"
  # 如果已存在证书，询问是否强制重新申请
  local force_flag=""
  if $ACME_SH --list 2>/dev/null | grep -q "^$domain\b"; then
    echo -n -e "${PURPLE}检测到已有证书，是否强制重新申请？[y/N]: ${NC}"; read rc
    case ${rc,,} in y|yes) force_flag="--force";; *) echo -e "${BLUE}将复用现有证书${NC}";; esac
  fi

  issue_via_nginx "$domain" "$include_www" "$force_flag" || return 1

  # 生成/更新 nginx 反向代理 (非80时生效)
  local nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  local domain_clean; domain_clean=$(echo "$domain" | sed 's/\.//g')
  if [[ $backend_port -ne 80 ]]; then
    cat > "$nginx_conf" <<EOF
server {
    listen 80;
    server_name $domain www.$domain;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain www.$domain;
    ssl_certificate /root/cert/${domain}.crt;
    ssl_certificate_key /root/cert/${domain}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:HIGH:!aNULL:!MD5:!DES:!3DES:!RC4;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$backend_port;
        client_max_body_size 20000m;
    }
    access_log /www/logs/${domain_clean}.log;
}
EOF
    systemctl reload nginx && echo -e "${GREEN}已更新 nginx SSL 反向代理配置${NC}" || { echo -e "${RED}nginx 配置更新失败${NC}"; return 1; }
  else
    echo -e "${BLUE}已生成 HTTP 配置并完成证书申请，如需启用 HTTPS 请手动更新 nginx 配置${NC}"
  fi

  echo -e "\n${GREEN}=== 完成 ===${NC}"
}

# 任务3: 进程
task_processes() { echo -e "\n${YELLOW}=== 当前运行的进程 (前10个) ===${NC}"; ps aux --sort=-%cpu | head -11; }
# 任务4: 网络
task_network() {
  echo -e "\n${YELLOW}=== 网络连接状态 ===${NC}";
  echo -e "${GREEN}网络接口:${NC}"; ip addr show 2>/dev/null || ifconfig;
  echo -e "\n${GREEN}活动连接:${NC}"; netstat -tuln 2>/dev/null | head -10 || ss -tuln | head -10;
}
# 任务5: 备份目录
task_backup() { echo -e "\n${YELLOW}=== 创建备份目录 ===${NC}"; local d="backup_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$d" && echo -e "${GREEN}已创建: $(pwd)/$d${NC}" || echo -e "${RED}创建失败${NC}"; }

pause() { echo ""; echo -n -e "${BLUE}按回车键继续...${NC}"; read; }

main() {
  require_root
  detect_system
  ensure_dependencies
  while true; do
    clear_screen
    show_welcome
    show_menu
    read choice
    case $choice in
      1) task_system_info; pause ;;
      2) task_acme_ssl; pause ;;
      3) task_processes; pause ;;
      4) task_network; pause ;;
      5) task_backup; pause ;;
      6) install_acmesh; pause ;;
      7) uninstall_acmesh; pause ;;
      8) issue_cf_tld; pause ;;
      9) issue_cf_wildcard; pause ;;
      10) list_cert; pause ;;
      11) revoke_cert; pause ;;
      12) renew_cert; pause ;;
      13) switch_ca; pause ;;
      0) echo -e "\n${GREEN}谢谢使用，再见！${NC}"; exit 0 ;;
      *) echo -e "\n${RED}无效选项，请输入 0-13 之间的数字！${NC}"; sleep 2 ;;
    esac
  done
}

main
