#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#stty erase ^?

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

idleleo=$(readlink -f "${BASH_SOURCE[0]}")

#=====================================================
#	System Request: Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	hello-yunshu
#	Dscription: Xray Onekey Management
#	Version: 2.0
#	email: admin@idleleo.com
#	Official document: hey.run
#=====================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
GreenW="\033[1;32m"
RedW="\033[1;31m"
#Yellow="\033[33m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
YellowBG="\033[43;30m"
Font="\033[0m"

#notification information
Info="${Green}[Notice]${Font}"
OK="${Green}[OK]${Font}"
Error="${RedW}[Error]${Font}"
Warning="${RedW}[Warning]${Font}"

shell_version="2.2.10"
shell_mode="Not Installed"
tls_mode="None"
ws_grpc_mode="None"
local_bin="/usr/local"
idleleo_dir="/etc/idleleo"
idleleo_conf_dir="${idleleo_dir}/conf"
log_dir="${idleleo_dir}/logs"
xray_bin_dir="${local_bin}/bin"
xray_conf_dir="${idleleo_conf_dir}/xray"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
xray_conf="${xray_conf_dir}/config.json"
xray_status_conf="${xray_conf_dir}/status_config.json"
xray_default_conf="${local_bin}/etc/xray/config.json"
nginx_conf="${nginx_conf_dir}/00-xray.conf"
nginx_ssl_conf="${nginx_conf_dir}/01-xray-80.conf"
nginx_upstream_conf="${nginx_conf_dir}/02-xray-server.conf"
idleleo_commend_file="/usr/bin/idleleo"
ssl_chainpath="${idleleo_dir}/cert"
nginx_dir="${local_bin}/nginx"
xray_info_file="${idleleo_dir}/info/xray_info.inf"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
auto_update_file="${idleleo_dir}/auto_update.sh"
ssl_update_file="${idleleo_dir}/ssl_update.sh"
myemali="my@example.com"
shell_version_tmp="${idleleo_dir}/tmp/shell_version.tmp"
get_versions_all=$(curl -s https://www.idleleo.com/api/xray_shell_versions)
read_config_status=1
reality_add_more="off"
reality_add_nginx="off"
old_config_status="off"
old_tls_mode="NULL"
random_num=$((RANDOM % 12 + 4))
[[ -f "${xray_qr_config_file}" ]] && info_extraction_all=$(jq -rc . ${xray_qr_config_file})

[[ ! -d ${log_dir} ]] && mkdir -p ${log_dir}
[[ ! -f "${log_dir}/install.log" ]] && touch ${log_dir}/install.log
LOG_FILE="${log_dir}/install.log"
LOG_MAX_SIZE=$((3 * 1024 * 1024))  # 3 MB
MAX_ARCHIVES=5

log() {
    if [ $(stat -c%s "$LOG_FILE" 2>/dev/null) -gt $LOG_MAX_SIZE ]; then
        log_rotate
    fi
    
    local message=$(echo -e "$1" | sed 's/\x1B\[\([0-9]\(;[0-9]\)*\)*m//g' | tr -d '\n')
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a $LOG_FILE >/dev/null
}

log_rotate() {
    local timestamp=$(date +%Y%m%d%H%M%S)
    local archived_log="${LOG_FILE}.${timestamp}.gz"
    
    # 添加 gzip 错误处理
    if ! gzip -c "$LOG_FILE" > "$archived_log"; then
        log_echo "${Error} ${RedBG} Log file archiving failed ${Font}"
        return 1
    fi
    
    # 添加清空日志文件的错误处理
    if ! :> "$LOG_FILE"; then
        log_echo "${Error} ${RedBG} Failed to clear log file ${Font}" 
        return 1
    fi
    
    log "Log file has been rotated and archived as $archived_log"
    
    rotate_archives
}

rotate_archives() {
    local archives=($(ls ${LOG_FILE}.*.gz 2>/dev/null))
    while [ ${#archives[@]} -gt $MAX_ARCHIVES ]; do
        oldest_archive=${archives[0]}
        rm "$oldest_archive"
        archives=($(ls ${LOG_FILE}.*.gz 2>/dev/null))
    done
}

log_echo() {
    local message=$(printf "%b" "$@")
    echo "$message"
    log "$message"
}

##兼容代码，未来删除
[[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p ${idleleo_dir}/tmp

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        log_echo "${OK} ${GreenBG} Current system is Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        [[ ! -f "${xray_qr_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        log_echo "${OK} ${GreenBG} Current system is Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        [[ ! -f "${xray_qr_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        log_echo "${OK} ${GreenBG} Current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        if [[ ! -f "${xray_qr_config_file}" ]]; then
            rm /var/lib/dpkg/lock || true
            dpkg --configure -a || true
            rm /var/lib/apt/lists/lock || true
            rm /var/cache/apt/archives/lock || true
            $INS update || true
        fi
    else
        log_echo "${Error} ${RedBG} Current system is ${ID} ${VERSION_ID} not in the supported system list, installation interrupted! ${Font}"
        exit 1
    fi
}

is_root() {
    if [[ 0 == $UID ]]; then
        log_echo "${OK} ${GreenBG} Current user is root, entering installation process ${Font}"
    else
        log_echo "${Error} ${RedBG} Current user is not root, please switch to root user and re-run the script! ${Font}"
        exit 1
    fi
}

check_and_create_user_group() {
    if ! getent group nogroup > /dev/null; then
        groupadd nogroup
    fi

    if ! id nobody > /dev/null 2>&1; then
        useradd -r -g nogroup -s /sbin/nologin -c "Unprivileged User" nobody
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        log_echo "${OK} ${GreenBG} $1 completed ${Font}"
        sleep 0.5
    else
        log_echo "${Error} ${RedBG} $1 failed ${Font}"
        exit 1
    fi
}

check_version() {
    echo ${get_versions_all} | jq -rc ".$1"
    [[ 0 -ne $? ]] && log_echo "${Error} ${RedBG} Online version detection failed, please try again later! ${Font}" && exit 1
}

pkg_install_judge() {
    if [[ "${ID}" == "centos" ]]; then
        yum list installed | grep -iw "^$1"
    else
        dpkg --get-selections | grep -iw "^$1" | grep -ivw "deinstall"
    fi
}

pkg_install() {
    install_array=(${1//,/ })
    install_status=1
    if [[ ${#install_array[@]} -gt 1 ]]; then
        for install_var in ${install_array[@]}; do
            if [[ -z $(pkg_install_judge "${install_var}") ]]; then
                ${INS} -y install ${install_var}
                install_status=0
            fi
        done
        if [[ ${install_status} == 0 ]]; then
            judge "Install ${1//,/ }"
        else
            log_echo "${OK} ${GreenBG} Already installed ${1//,/ } ${Font}"
            sleep 0.5
        fi
    else
        if [[ -z $(pkg_install_judge "$1") ]]; then
            ${INS} -y install $1
            judge "Install $1"
        else
            log_echo "${OK} ${GreenBG} Already installed $1 ${Font}"
            sleep 0.5
        fi
    fi
}

dependency_install() {
    pkg_install "bc,curl,dbus,git,jq,lsof,python3,qrencode,wget"
    if [[ "${ID}" == "centos" ]]; then
        pkg_install "crontabs"
    else
        pkg_install "cron"
    fi
    if [[ ! -f "/var/spool/cron/root" ]] && [[ ! -f "/var/spool/cron/crontabs/root" ]]; then
        if [[ "${ID}" == "centos" ]]; then
            touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
            systemctl start crond && systemctl enable crond >/dev/null 2>&1
            judge "Crontab autostart configuration"
        else
            touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
            systemctl start cron && systemctl enable cron >/dev/null 2>&1
            judge "Crontab autostart configuration"
        fi
    fi
    if [[ ${tls_mode} != "None" ]]; then
        if [[ "${ID}" == "centos" ]]; then
            pkg_install "epel-release,iputils,pcre,pcre-devel,zlib-devel,perl-IPC-Cmd"
        else
            pkg_install "iputils-ping,libpcre3,libpcre3-dev,zlib1g-dev"
        fi
        judge "Nginx link library installation"
    fi
}

read_optimize() {
    local prompt="$1" var_name="$2" default_value="${3:-NULL}" min_value="${4:-}" max_value="${5:-}" error_msg="${6:-Value is empty or out of range, please re-enter!}"
    local user_input

    read -rp "$prompt" user_input

    if [[ -z $user_input ]]; then
        if [[ $default_value != "NULL" ]]; then
            user_input=$default_value
        else
            log_echo "${Error} ${RedBG} Value is empty, please re-enter! ${Font}"
            read_optimize "$prompt" "$var_name" "$default_value" "$min_value" "$max_value" "$error_msg"
            return
        fi
    fi

    printf -v "$var_name" "%s" "$user_input"

    if [[ -n $min_value ]] && [[ -n $max_value ]]; then
        if (( user_input < min_value )) || (( user_input > max_value )); then
            log_echo "${Error} ${RedBG} $error_msg ${Font}"
            read_optimize "$prompt" "$var_name" "$default_value" "$min_value" "$max_value" "$error_msg"
            return
        fi
    fi
}

basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

create_directory() {
    if [[ ${tls_mode} != "None" ]]; then
        [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p ${nginx_conf_dir}
    fi
    [[ ! -d "${ssl_chainpath}" ]] && mkdir -p ${ssl_chainpath}
    [[ ! -d "${xray_conf_dir}" ]] && mkdir -p ${xray_conf_dir}
    [[ ! -d "${idleleo_dir}/info" ]] && mkdir -p ${idleleo_dir}/info
}

port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Determine the connection port ${Font}"
        read_optimize "Enter the connection port (default value:443):" "port" 443 0 65535 "Enter a value between 0-65535!"
        if [[ ${port} -eq 9443 ]] && [[ ${tls_mode} == "Reality" ]]; then
            echo -e "${Error} ${RedBG} Port 9443 is not allowed, please re-enter! ${Font}"
            read_optimize "Enter the connection port (default value:443):" "port" 443 0 65535 "Enter a value between 0-65535!"
        fi
    fi
}

ws_grpc_choose() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Please select the installation protocol ws/gRPC ${Font}"
        echo -e "${Red}1${Font}: ws (default)"
        echo "2: gRPC"
        echo "3: ws+gRPC"
        local choose_network
        read_optimize "Enter: " "choose_network" 1 1 3 "Enter a valid number"
        if [[ $choose_network == 2 ]]; then
            [[ ${shell_mode} == "Nginx+ws+TLS" ]] && shell_mode="Nginx+gRPC+TLS"
            [[ ${shell_mode} == "Reality" ]] && shell_mode="Reality+gRPC"
            [[ ${shell_mode} == "ws ONLY" ]] && shell_mode="gRPC ONLY"
            ws_grpc_mode="onlygRPC"
        elif [[ $choose_network == 3 ]]; then
            [[ ${shell_mode} == "Nginx+ws+TLS" ]] && shell_mode="Nginx+ws+gRPC+TLS"
            [[ ${shell_mode} == "Reality" ]] && shell_mode="Reality+ws+gRPC"
            [[ ${shell_mode} == "ws ONLY" ]] && shell_mode="ws+gRPC ONLY"
            ws_grpc_mode="all"
        else
            [[ ${shell_mode} == "Reality" ]] && shell_mode="Reality+ws"
            ws_grpc_mode="onlyws"
        fi
    fi
}

xray_reality_add_more_choose() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Whether to add simple ws/gRPC protocol for load balancing [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} If you are not sure about the specific use, do not choose! ${Font}"
        read -r reality_add_more_fq
        case $reality_add_more_fq in
        [yY][eE][sS] | [yY])
            reality_add_more="on"
            ws_grpc_choose
            ws_inbound_port_set
            grpc_inbound_port_set
            ws_path_set
            grpc_path_set
            port_exist_check "${xport}"
            port_exist_check "${gport}"
            ;;
        *)
            reality_add_more="off"
            ws_inbound_port_set
            grpc_inbound_port_set
            ws_path_set
            grpc_path_set
            log_echo "${OK} ${GreenBG} Skipped adding simple ws/gRPC protocol ${Font}"
            ;;
        esac
    fi
}

ws_grpc_qr() {
    artpath="None"
    artxport="None"
    artserviceName="None"
    artgport="None"
    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
        artxport=${xport}
        artpath=${path}
    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
        artgport=${gport}
        artserviceName=${serviceName}
    elif [[ ${ws_grpc_mode} == "all" ]]; then
        artxport=${xport}
        artpath=${path}
        artgport=${gport}
        artserviceName=${serviceName}
    fi
}

ws_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Do you need to customize the ws inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "Enter the custom ws inbound_port (do not use the same as other ports!):" "xport" "NULL" 0 65535 "Enter a value between 0-65535!"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            *)
                xport=$((RANDOM % 1000 + 10000))
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            esac
        else
            xport=$((RANDOM % 1000 + 20000))
        fi
    fi
}

grpc_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Do you need to customize the gRPC inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "Enter the custom gRPC inbound_port (do not use the same as other ports!):" "gport" "NULL" 0 65535 "Enter a value between 0-65535!"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            *)
                gport=$((RANDOM % 1000 + 10000))
                [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 10000))
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            esac
        else
            gport=$((RANDOM % 1000 + 30000))
        fi
    fi
}

firewall_set() {
    echo -e "\n"
    log_echo "${GreenBG} Do you need to set the firewall [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r firewall_set_fq
    case $firewall_set_fq in
    [yY][eE][sS] | [yY])
        if [[ "${ID}" == "centos" ]]; then
            pkg_install "iptables-services"
        else
            pkg_install "iptables-persistent"
        fi
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        if [[ ${tls_mode} == "TLS" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,80,${port} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,80,${port} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,80,${port} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,80,${port} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        fi
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${gport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${gport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${gport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${gport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xport},${gport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xport},${gport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport},${gport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xport},${gport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        fi
        if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
            service iptables save
            service iptables restart
            log_echo "${OK} ${GreenBG} Firewall restart completed ${Font}"
        else
            netfilter-persistent save
            systemctl restart iptables
            log_echo "${OK} ${GreenBG} Firewall restart completed ${Font}"
        fi
        log_echo "${OK} ${GreenBG} Opened firewall related ports ${Font}"
        log_echo "${GreenBG} If you modify the configuration, please note to close the firewall related ports ${Font}"
        log_echo "${OK} ${GreenBG} Configured Xray FullCone ${Font}"
        ;;
    *)
        log_echo "${OK} ${GreenBG} Skipped firewall settings ${Font}"
        ;;
    esac
}

ws_path_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_ws_path} == "yes" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Do you need to customize the ws disguise path [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r path_modify_fq
            case $path_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "Enter the custom ws disguise path (do not include “/”):" "path" "NULL"
                log_echo "${Green} ws disguise path: ${path} ${Font}"
                ;;
            *)
                path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                log_echo "${Green} ws disguise path: ${path} ${Font}"
                ;;
            esac
        else
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        fi
    elif [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Do you need to modify the ws disguise path [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r change_ws_path_fq
        case $change_ws_path_fq in
        [yY][eE][sS] | [yY])
            change_ws_path="yes"
            ws_path_set
            ;;
        *) ;;
        esac
    fi
}

grpc_path_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_grpc_path} == "yes" ]]; then
        if [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Do you need to customize the gRPC disguise path [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r path_modify_fq
            case $path_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "Enter the custom gRPC disguise path (do not include “/”):" "serviceName" "NULL"
                log_echo "${Green} gRPC disguise path: ${serviceName} ${Font}"
                ;;
            *)
                serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                log_echo "${Green} gRPC disguise path: ${serviceName} ${Font}"
                ;;
            esac
        else
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        fi
    elif [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Do you need to modify the gRPC disguise path [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r change_grpc_path_fq
        case $change_grpc_path_fq in
        [yY][eE][sS] | [yY])
            change_grpc_path="yes"
            grpc_path_set
            ;;
        *) ;;
        esac
    fi
}

email_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Do you need to customize the Xray username [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_email_fq
        case $custom_email_fq in
        [yY][eE][sS] | [yY])
            read_optimize "Enter a valid email (e.g. me@idleleo.com): " "custom_email" "NULL"
            ;;
        *)
            custom_email="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})@idleleo.com"
            ;;
        esac
        log_echo "${Green} Xray username (email): ${custom_email} ${Font}"
    fi
}

UUID_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Do you need to customize a string to map to UUIDv5 [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read_optimize "Enter a custom string (up to 30 characters):" "UUID5_char" "NULL"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo "${Green} Custom string: ${UUID5_char} ${Font}"
            log_echo "${Green} UUIDv5: ${UUID} ${Font}"
            echo -e "\n"
            ;;
        *)
            UUID5_char="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo "${Green} UUID mapping string: ${UUID5_char} ${Font}"
            log_echo "${Green} UUID: ${UUID} ${Font}"
            echo -e "\n"
            #[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
            ;;
        esac
    fi
}

target_set() {
    if [[ "on" == ${old_config_status} ]] && [[ $(info_extraction target) != null ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Detected that the target domain is already configured, do you want to keep it [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq
            case $old_host_fq in
            [nN][oO] | [nN])
                target_reset=1
                nginx_reality_serverNames_del
                ;;
            *)
                target_reset=0
                ;;
            esac
    fi
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]]; then
        local domain
        local output
        local curl_output
        pkg_install "nmap"

        while true; do
            echo -e "\n"
            log_echo "${GreenBG} Please enter a domain (e.g. bing.com)${Font}"
            log_echo "${Green}Domain requirements support TLSv1.3, X25519 and H2 as well as the domain is not redirected${Font}"
            read_optimize "Confirm that the domain meets the requirements and then enter: " "domain" "NULL"
            log_echo "${Green} Detecting the domain, please wait…${Font}"

            output=$(nmap --script ssl-enum-ciphers -p 443 "${domain}")
            curl_output=$(curl -I -k -m 5 "https://${domain}" 2>&1)
        
            # 检测TLSv1.3支持
            if ! echo "$output" | grep -q "TLSv1.3"; then
                log_echo "${Warning} ${YellowBG} The domain does not support TLSv1.3 ${YellowBG}${Font}"
            fi

            # 检测X25519支持
            if ! echo "$output" | grep -q "x25519"; then
                log_echo "${Warning} ${YellowBG} The domain does not support X25519 ${YellowBG}${Font}"
            fi

            # 检测HTTP/2支持
            if ! echo "$curl_output" | grep -q "HTTP/2"; then
                log_echo "${Warning} ${YellowBG} The domain does not support HTTP/2 ${YellowBG}${Font}"
            fi
        
            # 检测是否跳转
            if echo "$curl_output" | grep -i -q 'location:'; then
                log_echo "${Warning} ${YellowBG} The domain has been redirected ${YellowBG}${Font}"
            fi

            if ! echo "$output" | grep -q "TLSv1.3" || \
               ! echo "$output" | grep -q "x25519" || \
               ! echo "$curl_output" | grep -q "HTTP/2" || \
               echo "$curl_output" | grep -i -q 'location:'; then
                log_echo "${Warning} ${YellowBG} The domain may not meet all requirements ${YellowBG}${Font}"
                log_echo "${GreenBG} Do you still want to set this domain [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r force_set_fq
                case $force_set_fq in
                    [yY][eE][sS] | [yY])
                        target=$domain
                        break
                        ;;
                    *)
                        continue
                        ;;
                esac
            else
                log_echo "${OK} ${GreenBG} The domain ${domain} meets all requirements ${Font}"
                target=$domain
                break
            fi
        done
        log_echo "${Green} target domain: ${target} ${Font}"
    fi
}

serverNames_set() {
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]]; then
        local custom_serverNames_fq
        echo -e "\n"
        log_echo "${GreenBG} Do you need to modify the serverNames username for ${target} domain [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Green} Default is the domain itself of ${target}${Font}"
        echo -e "${Warning} ${YellowBG} If you are not sure about the specific use, do not continue! ${Font}"
        read -r custom_serverNames_fq
        case $custom_serverNames_fq in
        [yY][eE][sS] | [yY])
            read_optimize "Enter: " "serverNames" "NULL"
            ;;
        *)
            serverNames=$target
            ;;
        esac
        log_echo "${Green} serverNames: ${serverNames} ${Font}"
        echo -e "\n"
    fi
}

keys_set() {
    if [[ "on" != ${old_config_status} ]]; then
        local keys
        keys=$(${xray_bin_dir}/xray x25519 | tr '\n' ' ')
        privateKey=$(echo "${keys}" | awk -F"Private key: " '{print $2}' | awk '{print $1}')
        publicKey=$(echo "${keys}" | awk -F"Public key: " '{print $2}' | awk '{print $1}')
        log_echo "${Green} privateKey: ${privateKey} ${Font}"
        log_echo "${Green} publicKey: ${publicKey} ${Font}"
    fi
}

shortIds_set() {
    if [[ "on" != ${old_config_status} ]]; then
        pkg_install "openssl"
        shortIds=$(openssl rand -hex 4)
        log_echo "${Green} shortIds: ${shortIds} ${Font}"
    fi
}

nginx_upstream_server_set() {
    if [[ ${tls_mode} == "TLS" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Do you want to change the Nginx load balancing [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} If you are not sure about the specific use, do not continue! ${Font}"
        read -r nginx_upstream_server_fq
        case $nginx_upstream_server_fq in
        [yY][eE][sS] | [yY])
            echo -e "\n${GreenBG} Please select the protocol as ws or gRPC ${Font}"
            echo "1: ws"
            echo "2: gRPC"
            echo "3: Return"
            local upstream_choose
            read_optimize "Enter: " "upstream_choose" "NULL" 1 3 "Please enter a valid number"
            
            fm_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"
            fm_file_path=${nginx_conf_dir}
            if [ ! -f "${idleleo_dir}/file_manager.sh" ]; then
                log_echo "${Info} ${Green} The local file file_manager.sh does not exist, downloading... ${Font}"
                curl -sL "$fm_remote_url" -o "${idleleo_dir}/file_manager.sh"
                if [ $? -ne 0 ]; then
                    log_echo "${Error} ${RedBG} Download failed, please manually download and install the new version ${Font}"
                    return 1
                fi
                chmod +x "${idleleo_dir}/file_manager.sh"
            fi
            case $upstream_choose in
            1) source "${idleleo_dir}/file_manager.sh" wsServers ${fm_file_path} ;;
            2) source "${idleleo_dir}/file_manager.sh" grpcServers ${fm_file_path} ;;
            3) ;;
            *) 
                log_echo "${Error} ${RedBG} Invalid option, please try again ${Font}" 
                nginx_upstream_server_set
                ;;
            esac
            ;;
        *) ;;
        esac
    else
        log_echo "${Error} ${RedBG} The current mode does not support this operation! ${Font}"
    fi
}

nginx_servernames_server_set() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Do you want to change the Nginx serverNames configuration [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} If you are not sure about the specific use, do not continue! ${Font}"
        echo -e "${Info} ${GreenBG} The purpose of the configuration can be referred to in the article: (Coming Soon) ${Font}"
        read -r nginx_servernames_server_fq
        case $nginx_servernames_server_fq in
        [yY][eE][sS] | [yY])
            fm_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"
            fm_file_path=${nginx_conf_dir}
            if [ ! -f "${idleleo_dir}/file_manager.sh" ]; then
                log_echo "${Info} ${Green} The local file file_manager.sh does not exist, downloading... ${Font}"
                curl -sL "$fm_remote_url" -o "${idleleo_dir}/file_manager.sh"
                if [ $? -ne 0 ]; then
                    log_echo "${Error} ${RedBG} Download failed, please manually download and install the new version ${Font}"
                    return 1
                fi
                chmod +x "${idleleo_dir}/file_manager.sh"
            fi
            source "${idleleo_dir}/file_manager.sh" serverNames ${fm_file_path}
        ;;
        *) ;;
        esac
    else
        log_echo "${Error} ${RedBG} The current mode does not support this operation! ${Font}"
    fi
}

UUIDv5_tranc() {
    [[ $# = 0 ]] && return
    echo "import uuid;UUID_NAMESPACE=uuid.UUID('00000000-0000-0000-0000-000000000000');print(uuid.uuid5(UUID_NAMESPACE,'$1'));" | python3
}

modify_listen_address() {
    local modifynum modifynum2
    if [[ ${tls_mode} == "Reality" ]]; then
        modifynum=1
        modifynum2=2
    else
        modifynum=0
        modifynum2=1
    fi

    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
        jq --argjson modifynum "$modifynum" \
           '.inbounds[$modifynum].listen = "0.0.0.0"' "${xray_conf}" > "${xray_conf}.tmp"
        judge "Xray listen address modification"
    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
        jq --argjson modifynum2 "$modifynum2" \
           '.inbounds[$modifynum2].listen = "0.0.0.0"' "${xray_conf}" > "${xray_conf}.tmp"
        judge "Xray listen address modification"
    elif [[ ${ws_grpc_mode} == "all" ]]; then
        jq --argjson modifynum "$modifynum" --argjson modifynum2 "$modifynum2" \
           '.inbounds[$modifynum].listen = "0.0.0.0" | .inbounds[$modifynum2].listen = "0.0.0.0"' "${xray_conf}" > "${xray_conf}.tmp"
        judge "Xray listen address modification"
    fi
    mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_inbound_port() {
    if [[ ${tls_mode} == "Reality" ]]; then
        if [[ ${reality_add_nginx} == "off" ]]; then
            jq --argjson port "${port}" --argjson xport "${xport}" --argjson gport "${gport}" \
               '.inbounds[0].port = $port |
                .inbounds[1].port = $xport |
                .inbounds[2].port = $gport' "${xray_conf}" > "${xray_conf}.tmp"
            judge "Xray inbound port modification"
        else
            jq --argjson xport "${xport}" --argjson gport "${gport}" \
               '.inbounds[1].port = $xport |
                .inbounds[2].port = $gport' "${xray_conf}" > "${xray_conf}.tmp"
            judge "Xray inbound port modification"
        fi
    else
        jq --argjson xport "${xport}" --argjson gport "${gport}" \
           '.inbounds[0].port = $xport |
            .inbounds[1].port = $gport' "${xray_conf}" > "${xray_conf}.tmp"
        judge "Xray inbound port modification"
    fi
    mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_nginx_origin_conf() {
    sed -i "s/worker_processes  1;/worker_processes  auto;/" ${nginx_dir}/conf/nginx.conf
    sed -i "s/^\( *\)worker_connections  1024;.*/\1worker_connections  4096;/" ${nginx_dir}/conf/nginx.conf
    if [[ ${tls_mode} == "TLS" ]]; then
        sed -i "\$i include ${nginx_conf_dir}/*.conf;" ${nginx_dir}/conf/nginx.conf
    elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "\$a include ${nginx_conf_dir}/*.conf;" ${nginx_dir}/conf/nginx.conf
    fi
    sed -i "/http\( *\){/a \\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
    sed -i "/error_page.*504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 403;\\n\\t\\t}" ${nginx_dir}/conf/nginx.conf
}

modify_nginx_port() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "s/^\( *\)listen.*/\1listen ${port} reuseport so_keepalive=on backlog=65535;/" ${nginx_conf}
        judge "Nginx port modification"
    elif [[ ${tls_mode} == "TLS" ]]; then
        sed -i "2s/^\( *\).*ssl reuseport;$/\1listen ${port} ssl reuseport;/" ${nginx_conf}
        sed -i "3s/^\( *\).*ssl reuseport;$/\1listen [::]:${port} ssl reuseport;/" ${nginx_conf}
        sed -i "4s/^\( *\).*quic reuseport;$/\1listen ${port} quic reuseport;/" ${nginx_conf}
        sed -i "5s/^\( *\).*quic reuseport;$/\1listen [::]:${port} quic reuseport;/" ${nginx_conf}
        judge "Xray port modification"
    fi
    log_echo "${Green} Port number: ${port} ${Font}"
}

modify_nginx_ssl_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" ${nginx_dir}/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${domain};/g" ${nginx_ssl_conf}
    sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${domain}\$request_uri;/" ${nginx_ssl_conf}
}

modify_nginx_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" ${nginx_dir}/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    if [[ ${tls_mode} == "TLS" ]]; then
        sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${domain};/g" ${nginx_conf}
        sed -i "s/^\( *\)location ws$/\1location \/${path}/" ${nginx_conf}
        sed -i "s/^\( *\)location grpc$/\1location \/${serviceName}/" ${nginx_conf}
        sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${domain}\$request_uri;/" ${nginx_conf}
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            sed -i "s/^\( *\)#proxy_pass\(.*\)/\1proxy_pass\2/" ${nginx_conf}
            sed -i "s/^\( *\)#proxy_redirect default;/\1proxy_redirect default;/" ${nginx_conf}
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" ${nginx_conf}
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            sed -i "s/^\( *\)#proxy_pass\(.*\)/\1proxy_pass\2/" ${nginx_conf}
            sed -i "s/^\( *\)#proxy_redirect default;/\1proxy_redirect default;/" ${nginx_conf}
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" ${nginx_conf}
        fi
    fi
}

nginx_servers_add() {
    touch ${nginx_conf_dir}/127.0.0.1.wsServers
    cat >${nginx_conf_dir}/127.0.0.1.wsServers <<EOF
server 127.0.0.1:${xport} weight=50 max_fails=2 fail_timeout=10;
EOF
    touch ${nginx_conf_dir}/127.0.0.1.grpcServers
    cat >${nginx_conf_dir}/127.0.0.1.grpcServers<<EOF
server 127.0.0.1:${gport} weight=50 max_fails=2 fail_timeout=10;
EOF
}

modify_path() {
    sed -i "s/^\( *\)\"path\".*/\1\"path\": \"\/${path}\"/" ${xray_conf}
    sed -i "s/^\( *\)\"serviceName\".*/\1\"serviceName\": \"${serviceName}\",/" ${xray_conf}
    if [[ ${tls_mode} != "Reality" ]] || [[ "$reality_add_more" == "off" ]]; then
        judge "Xray disguise path modification"
    else
        log_echo "${Warning} ${YellowBG} Reality does not support path ${Font}"
    fi
}

modify_email_address() {
    if [[ $(jq -r '.inbounds[0].settings.clients|length' ${xray_conf}) == 1 ]] && [[ $(jq -r '.inbounds[1].settings.clients|length' ${xray_conf}) == 1 ]]; then
        sed -i "s/^\( *\)\"email\".*/\1\"email\": \"${custom_email}\"/g" ${xray_conf}
        judge "Xray username modification"
    else
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} Please delete the extra users first ${Font}"
    fi
}

modify_UUID() {
    if [[ $(jq -r '.inbounds[0].settings.clients|length' ${xray_conf}) == 1 ]] && [[ $(jq -r '.inbounds[1].settings.clients|length' ${xray_conf}) == 1 ]]; then
        sed -i "s/^\( *\)\"id\".*/\1\"id\": \"${UUID}\",/g" ${xray_conf}
        judge "Xray UUID modification"
    else
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} Please delete the extra users ${Font}"
    fi
}

modify_target_serverNames() {
  jq --arg target "${target}:443" --arg serverNames "${serverNames}" '
     .inbounds[0].streamSettings.realitySettings.target = $target |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$serverNames]' "${xray_conf}" > "${xray_conf}.tmp"
  judge "target serverNames configuration modification"
  mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_privateKey_shortIds() {
  jq --arg privateKey "${privateKey}" --arg shortIds "${shortIds}" '
     .inbounds[0].streamSettings.realitySettings.privateKey = $privateKey |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortIds]' "${xray_conf}" > "${xray_conf}.tmp"
  judge "privateKey and shortIds configuration modification"
  mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_reality_listen_address () {
    jq '.inbounds[0].listen = "127.0.0.1"' "${xray_conf}" > "${xray_conf}.tmp"
    mv "${xray_conf}.tmp" "${xray_conf}"
    judge "Xray reality listen address modification"
}

xray_privilege_escalation() {
    if [[ -n "$(grep "User=nobody" ${xray_systemd_file})" ]]; then
        log_echo "${OK} ${GreenBG} Detected Xray's permission control, starting the cleanup program ${Font}"
        chmod -fR a+rw /var/log/xray/
        chown -fR nobody:nogroup /var/log/xray/
        [[ -f "${ssl_chainpath}/xray.key" ]] && chown -fR nobody:nogroup ${ssl_chainpath}/*
    fi
    log_echo "${OK} ${GreenBG} Xray cleanup completed ${Font}"
}

xray_install() {
    if [[ $(xray version) == "" ]] || [[ ! -f "${xray_conf}" ]]; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
        judge "Install Xray"
        systemctl daemon-reload
        xray_privilege_escalation
        [[ -f "${xray_default_conf}" ]] && rm -rf ${xray_default_conf}
        ln -s ${xray_conf} ${xray_default_conf}
    else
        log_echo "${OK} ${GreenBG} Xray is already installed ${Font}"
    fi
}

xray_update() {
    [[ ! -d "${local_bin}/etc/xray" ]] && log_echo "${GreenBG} If the update is ineffective, it is recommended to uninstall and reinstall directly! ${Font}"
    log_echo "${Warning} ${GreenBG} Some new features require reinstallation to take effect ${Font}"
    xray_online_version=$(check_version xray_online_version)
    ## xray_online_version=$(check_version xray_online_pre_version)
    ## if [[ $(info_extraction xray_version) != ${xray_online_version} ]] && [[ ${xray_version} != ${xray_online_version} ]]; then
    if [[ $(info_extraction xray_version) != ${xray_online_version} ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            log_echo "${Warning} ${GreenBG} Detected the existence of the latest version ${Font}"
            log_echo "${Warning} ${GreenBG} The script may not be compatible with this version ${Font}"
            log_echo "${Warning} ${GreenBG} Do you want to update [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_test_fq
        else
            xray_test_fq=1
        fi
        case $xray_test_fq in
        [yY][eE][sS] | [yY])
            log_echo "${OK} ${GreenBG} About to upgrade Xray! ${Font}"
            systemctl stop xray
            ## xray_version=${xray_online_version}
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
            judge "Xray upgrade"
            ;;
        *)
            log_echo "${OK} ${GreenBG} About to upgrade/reinstall Xray! ${Font}"
            systemctl stop xray
            xray_version=$(info_extraction xray_version)
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
            judge "Xray upgrade"
            ;;
        esac
    else
        timeout "Upgrade/reinstall Xray!"
        systemctl stop xray
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
        judge "Xray upgrade"
    fi
    xray_privilege_escalation
    [[ -f "${xray_default_conf}" ]] && rm -rf ${xray_default_conf}
    ln -s ${xray_conf} ${xray_default_conf}
    jq --arg xray_version "${xray_version}" '.xray_version = $xray_version' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
    mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
    systemctl daemon-reload
    systemctl start xray
}

reality_nginx_add_fq() {
    echo -e "\n"
    log_echo "${Warning} ${Green} The Reality protocol has the risk of traffic leakage ${Font}"
    log_echo "${Warning} ${Green} This risk exists when the target URL is accelerated by CDN ${Font}"
    log_echo "${GreenBG} Do you want to add nginx as a front-end protection (recommended) [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r reality_nginx_add_fq
    case $reality_nginx_add_fq in
        [nN][oO] | [nN])
            log_echo "${OK} ${GreenBG} Skipped installing nginx ${Font}"
        ;;
        *)
            reality_add_nginx="on"
            nginx_exist_check
            nginx_systemd
            nginx_reality_conf_add
            nginx_reality_serverNames_add
        ;;

    esac
}

nginx_exist_check() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]] && [[ "$(info_extraction nginx_build_version)" == "null" ]]; then
        if [[ -d "${nginx_conf_dir}" ]]; then
            rm -rf ${nginx_conf_dir}/*.conf
            if [[ -f "${nginx_conf_dir}/nginx.default" ]]; then
                cp -fp ${nginx_conf_dir}/nginx.default ${nginx_dir}/conf/nginx.conf
            elif [[ -f "${nginx_dir}/conf/nginx.conf.default" ]]; then
                cp -fp ${nginx_dir}/conf/nginx.conf.default ${nginx_dir}/conf/nginx.conf
            else
                sed -i "/if \(.*\) {$/,+2d" ${nginx_dir}/conf/nginx.conf
                sed -i "/^include.*\*\.conf;$/d" ${nginx_dir}/conf/nginx.conf
            fi
        else
            sed -i "/if \(.*\) {$/,+2d" ${nginx_dir}/conf/nginx.conf
            sed -i "/^include.*\*\.conf;$/d" ${nginx_dir}/conf/nginx.conf
        fi
        modify_nginx_origin_conf
        log_echo "${OK} ${GreenBG} Nginx already exists, skipped the compilation and installation process ${Font}"
    #兼容代码，下个大版本删除
    elif [[ -d "/etc/nginx" ]] && [[ "$(info_extraction nginx_version)" == "null" ]]; then
        log_echo "${Error} ${GreenBG} Detected an old version of nginx installed! ${Font}"
        log_echo "${Warning} ${GreenBG} Please make a backup first ${Font}"
        log_echo "${GreenBG} Do you need to delete (please delete) [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r remove_nginx_fq
        case $remove_nginx_fq in
        [nN][oO] | [nN])
        log_echo "${OK} ${GreenBG} Skipped deleting nginx ${Font}"
        source "$idleleo"
            ;;
        *)
            rm -rf /etc/nginx/
            [[ -f "${nginx_systemd_file}" ]] && rm -rf ${nginx_systemd_file}
            [[ -d "${nginx_conf_dir}" ]] && rm -rf ${nginx_conf_dir}/*.conf
            log_echo "${Warning} ${GreenBG} The log directory has been changed, the log deletion needs to be re-configured! ${Font}"
            nginx_install
            ;;
        esac
    #兼容代码结束
    elif [[ -d "/etc/nginx" ]] && [[ "$(info_extraction nginx_version)" == "null" ]]; then
        log_echo "${Error} ${RedBG} Detected other packages installed Nginx, continuing the installation will cause conflicts, please deal with it and install! ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    local latest_version=$(check_version nginx_build_online_version)
    local temp_dir=$(mktemp -d)
    local current_dir=$(pwd)

    cd "$temp_dir" || exit

    log_echo "${OK} ${GreenBG} About to download the pre-compiled Nginx ${Font}"
    local url="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${latest_version}/xray-nginx-custom.tar.gz"
    wget -q --show-progress --progress=bar:force:noscroll "$url" -O xray-nginx-custom.tar.gz
    tar -xzvf xray-nginx-custom.tar.gz -C ./
    [[ -d ${nginx_dir} ]] && rm -rf "${nginx_dir}"
    mv ./nginx "${nginx_dir}"
    
    cp -fp ${nginx_dir}/conf/nginx.conf ${nginx_conf_dir}/nginx.default

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    modify_nginx_origin_conf

    # 删除临时文件
    cd "$current_dir" && rm -rf "$temp_dir"
    chown -fR nobody:nogroup "${nginx_dir}"
    chmod -fR 755 "${nginx_dir}"
}

nginx_update() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]]; then
        if [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
            ip_check
            if [[ -f "${xray_qr_config_file}" ]]; then
                domain=$(info_extraction host)
                if [[ ${tls_mode} == "TLS" ]]; then
                    port=$(info_extraction port)
                    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$((RANDOM % 1000 + 30000))
                        [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                        xport=$((RANDOM % 1000 + 20000))
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${ws_grpc_mode} == "all" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                    fi
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "Nginx configuration file is incomplete, exit update!" && exit 1
                        log_echo "${Error} ${RedBG} Configuration file is incomplete, exit update ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
                    port=$(info_extraction port)
                    serverNames=$(info_extraction serverNames)
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "Nginx configuration file is incomplete, exit update!" && exit 1
                        log_echo "${Error} ${RedBG} Configuration file is incomplete, exit update ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "None" ]]; then
                    [[ ${auto_update} == "YES" ]] && echo "The current installation mode does not require Nginx!" && exit 1
                    log_echo "${Error} ${RedBG} The current installation mode does not require Nginx! ${Font}"
                    return 1
                fi
            else
                [[ ${auto_update} == "YES" ]] && echo "Nginx configuration file does not exist, exit update!" && exit 1
                log_echo "${Error} ${RedBG} Nginx configuration file does not exist, exit update ${Font}"
                return 1
            fi
            service_stop
            timeout "Deleting old Nginx!"
            rm -rf ${nginx_dir}
            if [[ ${auto_update} != "YES" ]]; then
                echo -e "\n"
                log_echo "${GreenBG} Do you want to keep the original Nginx configuration file [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                read -r save_originconf_fq
            else
                save_originconf_fq=1
            fi
            case $save_originconf_fq in
            [nN][oO] | [nN])
                rm -rf ${nginx_conf_dir}/*.conf
                log_echo "${OK} ${GreenBG} Original configuration file has been deleted! ${Font}"
                ;;
            *)
                save_originconf="Yes"
                log_echo "${OK} ${GreenBG} Original configuration file has been kept! ${Font}"
                ;;
            esac
            nginx_install
            if [[ ${tls_mode} == "TLS" ]] && [[ ${save_originconf} != "Yes" ]]; then
                nginx_ssl_conf_add
                nginx_conf_add
                nginx_servers_conf_add
            elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]] && [[ ${save_originconf} != "Yes" ]]; then
                nginx_reality_conf_add
            fi
            service_start
            jq --arg nginx_build_version "${nginx_build_version}" '.nginx_build_version = $nginx_build_version' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            judge "Nginx upgrade"
        else
            log_echo "${OK} ${GreenBG} Nginx is already the latest version ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} Nginx is not installed ${Font}"
    fi
}

auto_update() {
    if [[ "${ID}" == "centos" ]]; then
        crontab_file="/var/spool/cron/root"
    else
        crontab_file="/var/spool/cron/crontabs/root"
    fi
    if [[ ! -f "${auto_update_file}" ]] || [[ $(crontab -l | grep -c "auto_update.sh") -lt 1 ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Set the background automatic update program (including: script/Xray/Nginx) ${Font}"
        log_echo "${GreenBG} There may be compatibility issues with automatic updates, be cautious to enable ${Font}"
        log_echo "${GreenBG} Do you want to enable [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_fq
        case $auto_update_fq in
        [yY][eE][sS] | [yY])
            wget -N -P ${idleleo_dir} --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/auto_update.sh && chmod +x ${auto_update_file}
            echo "0 1 15 * * bash ${auto_update_file}" >>${crontab_file}
            judge "Set automatic update"
            ;;
        *) ;;
        esac
    else
        log_echo "${OK} ${GreenBG} Automatic update has already been set ${Font}"
        log_echo "${GreenBG} Do you want to disable it [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_close_fq
        case $auto_update_fq in
        [yY][eE][sS] | [yY])
            sed -i "/auto_update.sh/d" ${crontab_file}
            rm -rf ${auto_update_file}
            judge "Delete automatic update"
            ;;
        *) ;;
        esac
    fi
}

ssl_install() {
    pkg_install "socat"
    judge "Install SSL certificate generation script dependency"
    curl https://get.acme.sh | sh -s email=${custom_email}
    judge "Install SSL certificate generation script"
}

domain_check() {
    if [[ "on" == ${old_config_status} ]] && [[ $(info_extraction host) != null ]] && [[ $(info_extraction ip_version) != null ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Detected that the original domain configuration exists, do you want to skip the domain setting [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r old_host_fq
        case $old_host_fq in
        [nN][oO] | [nN]) ;;
        *)
            domain=$(info_extraction host)
            ip_version=$(info_extraction ip_version)
            if [[ ${ip_version} == "IPv4" ]]; then
                local_ip=$(curl -4 ip.sb)
            elif [[ ${ip_version} == "IPv6" ]]; then
                local_ip=$(curl -6 ip.sb)
            else
                local_ip=${ip_version}
            fi
            log_echo "${OK} ${GreenBG} Skipped domain setting ${Font}"
            return 0
            ;;
        esac
    fi
    echo -e "\n"
    log_echo "${GreenBG} Determine the domain information ${Font}"
    read_optimize "Please enter your domain information (e.g. www.idleleo.com):" "domain" "NULL"
    echo -e "\n${GreenBG} Please select the public IP (IPv4/IPv6) or manually enter the domain ${Font}"
    echo -e "${Red}1${Font}: IPv4 (default)"
    echo "2: IPv6 (not recommended)"
    echo "3: Domain"
    local ip_version_fq
    read_optimize "Enter: " "ip_version_fq" 1 1 3 "Please enter a valid number"
    log_echo "${OK} ${GreenBG} Getting public IP information, please wait patiently ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        local_ip=$(curl -4 ip.sb)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
        ip_version="IPv4"
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(curl -6 ip.sb)
        domain_ip=$(ping -6 "${domain}" -c 1 | sed '2{s/[^(]*(//;s/).*//;q}' | tail -n +2)
        ip_version="IPv6"
    elif [[ ${ip_version_fq} == 3 ]]; then
        log_echo "${Warning} ${GreenBG} This option is for servers that only provide domain access to the server ${Font}"
        log_echo "${Warning} ${GreenBG} Note that the server provider adds a CNAME record to the domain ${Font}"
        read_optimize "Enter: " "local_ip" "NULL"
        ip_version=${local_ip}
    else
        local_ip=$(curl -4 ip.sb)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
        ip_version="IPv4"
    fi
    log_echo "Domain DNS resolution IP: ${domain_ip}"
    log_echo "Public IP/domain: ${local_ip}"
    if [[ ${ip_version_fq} != 3 ]] && [[ ${local_ip} == ${domain_ip} ]]; then
        log_echo "${OK} ${GreenBG} The domain DNS resolution IP matches the public IP ${Font}"
    else
        log_echo "${Warning} ${YellowBG} Please make sure that the domain has added the correct A/AAAA record, otherwise Xray will not be able to work properly ${Font}"
        log_echo "${Error} ${RedBG} The domain DNS resolution IP does not match the public IP, please select: ${Font}"
        echo "1: Continue installation"
        echo "2: Re-enter"
        log_echo "${Red}3${Font}: Terminate installation (default)"
        local install
        read_optimize "Enter: " "install" 3 1 3 "Please enter a valid number"
        case $install in
        1)
            log_echo "${OK} ${GreenBG} Continue installation ${Font}"
            ;;
        2)
            domain_check
            ;;
        *)
            log_echo "${Error} ${RedBG} Installation terminated ${Font}"
            exit 2
            ;;
        esac
    fi
}

ip_check() {
    if [[ "on" == ${old_config_status} || ${auto_update} == "YES" ]] && [[ $(info_extraction host) != null ]] && [[ $(info_extraction ip_version) != null ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Detected that the original IP configuration exists, do you want to skip the IP setting [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq
        else
            old_host_fq=1
        fi
        case $old_host_fq in
        [nN][oO] | [nN]) ;;
        *)
            ip_version=$(info_extraction ip_version)
            if [[ ${ip_version} == "IPv4" ]]; then
                local_ip=$(curl -4 ip.sb)
            elif [[ ${ip_version} == "IPv6" ]]; then
                local_ip=$(curl -6 ip.sb)
            else
                local_ip=${ip_version}
            fi
            echo -e "\n"
            log_echo "${OK} ${GreenBG} Skipped IP setting ${Font}"
            return 0
            ;;
        esac
    # ##兼容代码，未来删除
    # elif [[ ${auto_update} == "YES" ]] && [[ $(info_extraction ip_version) == null ]]; then
    #     echo "Unable to test IP version, skip Nginx update!" >>${log_file}
    #     echo "(The reason is that the script version is low and cannot be compatible, reinstall can solve the problem)" >>${log_file}
    #     exit 1
    fi
    echo -e "\n"
    log_echo "${GreenBG} Determine the public IP information ${Font}"
    log_echo "${GreenBG} Please select the public IP as IPv4 or IPv6 ${Font}"
    echo -e "${Red}1${Font}: IPv4 (default)"
    echo "2: IPv6 (not recommended)"
    echo "3: Manually enter"
    local ip_version_fq
    read_optimize "Enter: " "ip_version_fq" 1 1 3 "Please enter a valid number"
    [[ -z ${ip_version_fq} ]] && ip_version=1
    log_echo "${OK} ${GreenBG} Getting public IP information, please wait patiently ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        local_ip=$(curl -4 ip.sb)
        ip_version="IPv4"
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(curl -6 ip.sb)
        ip_version="IPv6"
    elif [[ ${ip_version_fq} == 3 ]]; then
        read_optimize "Enter: " "local_ip" "NULL"
        ip_version=${local_ip}
    else
        local_ip=$(curl -4 ip.sb)
        ip_version="IPv4"
    fi
    log_echo "Public IP/domain: ${local_ip}"
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        log_echo "${OK} ${GreenBG} Port $1 is not occupied ${Font}"
    else
        log_echo "${Error} ${RedBG} Detected that port $1 is occupied, the following is the port $1 occupation information ${Font}"
        lsof -i:"$1"
        timeout "Trying to automatically kill the occupying process!"
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        log_echo "${OK} ${GreenBG} Kill completed ${Font}"
    fi
}

acme() {
    systemctl restart nginx
    #暂时解决ca问题
    if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --server letsencrypt --keylength ec-256 --force --test; then
    #if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --keylength ec-256 --force --test; then
        log_echo "${OK} ${GreenBG} SSL certificate test issuance successful, starting formal issuance ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
    else
        log_echo "${Error} ${RedBG} SSL certificate test issuance failed ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --server letsencrypt --keylength ec-256 --force; then
    #if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --keylength ec-256 --force; then
        log_echo "${OK} ${GreenBG} SSL certificate generation successful ${Font}"
        mkdir -p ${ssl_chainpath}
        if "$HOME"/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc --force; then
            chmod -f a+rw ${ssl_chainpath}/xray.crt
            chmod -f a+rw ${ssl_chainpath}/xray.key
            chown -fR nobody:nogroup ${ssl_chainpath}/*
            log_echo "${OK} ${GreenBG} Certificate configuration successful ${Font}"
            systemctl stop nginx
        fi
    else
        log_echo "${Error} ${RedBG} SSL certificate generation failed ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add() {
    if [[ $(info_extraction multi_user) != "yes" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            wget --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_tls/config.json -O ${xray_conf}
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "Reality" ]]; then
            wget --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_reality/config.json -O ${xray_conf}
            modify_target_serverNames
            modify_privateKey_shortIds
            xray_reality_add_more
        elif [[ ${tls_mode} == "None" ]]; then
            wget --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_tls/config.json -O ${xray_conf}
            modify_listen_address
            modify_path
            modify_inbound_port
        fi
        modify_email_address
        modify_UUID
    else
        echo -e "\n"
        log_echo "${Warning} ${GreenBG} Detected too many users in Xray configuration ${Font}"
        log_echo "${GreenBG} Do you want to keep the original Xray configuration file [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r save_originxray_fq
        case $save_originxray_fq in
        [nN][oO] | [nN])
            rm -rf ${xray_conf}
            log_echo "${OK} ${GreenBG} Original configuration file has been deleted! ${Font}"
            xray_conf_add
            ;;
        *) ;;
        esac
    fi
}

xray_reality_add_more() {
    if [[ ${reality_add_more} == "on" ]]; then
        modify_path
        modify_listen_address
        modify_inbound_port
        judge "Add simple ws/gRPC protocol"
    else
        modify_path
        modify_inbound_port
    fi

    if [[ ${reality_add_nginx} == "on" ]]; then
        modify_reality_listen_address
    fi
}

old_config_exist_check() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        if [[ ${old_tls_mode} == ${tls_mode} ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Detected the configuration file, do you want to read the configuration file [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [nN][oO] | [nN])
                rm -rf ${xray_qr_config_file}
                log_echo "${OK} ${GreenBG} The configuration file has been deleted ${Font}"
                ;;
            *)
                log_echo "${OK} ${GreenBG} The configuration file has been kept ${Font}"
                old_config_status="on"
                old_config_input
                ;;
            esac
        else
            echo -e "\n"
            log_echo "${Warning} ${GreenBG} Detected that the current installation mode is not consistent with the installation mode of the configuration file ${Font}"
            log_echo "${GreenBG} Do you want to keep the configuration file (strongly not recommended) [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                log_echo "${Warning} ${GreenBG} Please make sure the configuration file is correct ${Font}"
                log_echo "${OK} ${GreenBG} The configuration file has been kept ${Font}"
                menu
                ;;
            *)
                rm -rf ${xray_qr_config_file}
                log_echo "${OK} ${GreenBG} The configuration file has been deleted ${Font}"
                ;;
            esac
        fi
    fi
}

old_config_input() {
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
    custom_email=$(info_extraction email)
    UUID5_char=$(info_extraction idc)
    UUID=$(info_extraction id)
    if [[ ${tls_mode} == "TLS" ]]; then
        port=$(info_extraction port)
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$((RANDOM % 1000 + 30000))
            [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
            xport=$((RANDOM % 1000 + 20000))
            [[ ${gport} == ${xport} ]] && xport=$((RANDOM % 1000 + 20000))
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        port=$(info_extraction port)
        target=$(info_extraction target)
        serverNames=$(info_extraction serverNames)
        privateKey=$(info_extraction privateKey)
        publicKey=$(info_extraction publicKey)
        shortIds=$(info_extraction shortIds)
        if [[ ${reality_add_more} == "on" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                xport=$(info_extraction ws_port)
                path=$(info_extraction ws_path)
                gport=$((RANDOM % 1000 + 30000))
                [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
                serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                gport=$(info_extraction grpc_port)
                serviceName=$(info_extraction grpc_serviceName)
                xport=$((RANDOM % 1000 + 20000))
                [[ ${gport} == ${xport} ]] && xport=$((RANDOM % 1000 + 20000))
                path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                xport=$(info_extraction ws_port)
                path=$(info_extraction ws_path)
                gport=$(info_extraction grpc_port)
                serviceName=$(info_extraction grpc_serviceName)
            fi
        else
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            xport=$((RANDOM % 1000 + 20000))
            gport=$((RANDOM % 1000 + 30000))
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$((RANDOM % 1000 + 30000))
            [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
            xport=$((RANDOM % 1000 + 20000))
            [[ ${gport} == ${xport} ]] && xport=$((RANDOM % 1000 + 20000))
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
    fi
    if [[ 0 -eq ${read_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Detected that the configuration file is incomplete, do you want to keep the configuration file [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        [yY][eE][sS] | [yY])
            old_config_status="off"
            log_echo "${OK} ${GreenBG} The configuration file has been kept ${Font}"
            ;;
        *)
            rm -rf ${xray_qr_config_file}
            old_config_status="off"
            log_echo "${OK} ${GreenBG} The configuration file has been deleted ${Font}"
            ;;
        esac
    fi
}

nginx_ssl_conf_add() {
    touch ${nginx_ssl_conf}
    cat >${nginx_ssl_conf} <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name serveraddr.com;

    location ^~ /.well-known/acme-challenge/ {
        root ${idleleo_dir}/conf;
        default_type "text/plain"; 
        allow all;
    } 
    location = /.well-known/acme-challenge/ {
        return 404; 
    }

    location / {
        return 301 https://www.idleleo.com\$request_uri;
    }
}
EOF
    modify_nginx_ssl_other
    judge "Nginx SSL configuration modification"
}

nginx_conf_add() {
    touch ${nginx_conf}
    cat >${nginx_conf} <<EOF
server {
    listen 443 ssl reuseport;
    listen [::]:443 ssl reuseport;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;

    http2 on;
    set_real_ip_from    127.0.0.1;
    real_ip_header      X-Forwarded-For;
    real_ip_recursive   on;
    ssl_certificate       ${idleleo_dir}/cert/xray.crt;
    ssl_certificate_key   ${idleleo_dir}/cert/xray.key;
    ssl_protocols         TLSv1.3;
    ssl_ciphers           TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA;
    server_name           serveraddr.com;
    index index.html index.htm;
    root /403.html;
    error_page 403 https://www.idleleo.com/helloworld;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_early_data on;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000";

    location grpc
    {
        #grpc_pass grpc://xray-grpc-server;
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        client_max_body_size 0;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Early-Data \$ssl_early_data;
    }

    location ws
    {
        #proxy_pass http://xray-ws-server;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    location /
    {
        return 403;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx configuration modification"
}

nginx_reality_conf_add() {
    touch ${nginx_conf}
    cat >${nginx_conf} <<EOF

stream {
    map \$ssl_preread_server_name \$stream_map {
        include ${nginx_conf_dir}/*.serverNames;
    }
 
    upstream reality {
        server 127.0.0.1:9443;
    }

    server {
        listen 443 reuseport so_keepalive=on backlog=65535;
        proxy_pass \$stream_map;
        ssl_preread on;
        #proxy_protocol on;
        
        # Timeout settings
        proxy_connect_timeout 20s;       # Connection timeout
        proxy_timeout 300s;            # Data transfer timeout
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx configuration modification"
}

nginx_reality_serverNames_add () {
    touch ${nginx_conf_dir}/${serverNames}.serverNames
    cat >${nginx_conf_dir}/${serverNames}.serverNames <<EOF
${serverNames} reality;
EOF
    # modify_nginx_reality_serverNames
    judge "Nginx serverNames configuration modification"

}

nginx_reality_serverNames_del () {
    [[ -f "${nginx_conf_dir}/${serverNames}.serverNames" ]] && rm -f "${nginx_conf_dir}/${serverNames}.serverNames"
    # modify_nginx_reality_serverNames
    judge "Nginx serverNames configuration deletion"

}

nginx_servers_conf_add() {
    touch ${nginx_upstream_conf}
    cat >${nginx_upstream_conf} <<EOF
upstream xray-ws-server {
    include ${nginx_conf_dir}/*.wsServers;
}

upstream xray-grpc-server {
    include ${nginx_conf_dir}/*.grpcServers;
}
EOF
    nginx_servers_add
    judge "Nginx servers configuration modification"
}

enable_process_systemd() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl enable nginx && judge "Set Nginx to start on boot"
    fi
    systemctl enable xray
    judge "Set Xray to start on boot"
}

disable_process_systemd() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx && systemctl disable nginx && judge "Disable Nginx from starting on boot"
    fi
    systemctl disable xray
    judge "Disable Xray from starting on boot"
}

stop_service_all() {
    [[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx && systemctl disable nginx
    systemctl stop xray
    systemctl disable xray
    log_echo "${OK} ${GreenBG} Stopped existing services ${Font}"
}

service_restart() {
    systemctl daemon-reload
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl restart nginx && judge "Nginx restart"
    fi
    systemctl restart xray
    judge "Xray restart"
}

service_start() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl start nginx && judge "Nginx start"
    fi
    systemctl start xray
    judge "Xray start"
}

service_stop() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx && judge "Nginx stop"
    fi
    systemctl stop xray
    judge "Xray stop"
}

acme_cron_update() {
    if [[ ${tls_mode} == "TLS" ]]; then
        local crontab_file
        if [[ "${ID}" == "centos" ]]; then
            crontab_file="/var/spool/cron/root"
        else
            crontab_file="/var/spool/cron/crontabs/root"
        fi
        if [[ -f "${ssl_update_file}" ]] && [[ $(crontab -l | grep -c "ssl_update.sh") == "1" ]]; then
            echo -e "\n"
            log_echo "${Warning} ${Green} The new version has automatically set the certificate automatic update ${Font}"
            log_echo "${Warning} ${Green} The old version should be deleted in time (the abandoned version of the certificate automatic update)! ${Font}"
            log_echo "${Green} The certificate automatic update has been set ${Font}"
            log_echo "${Green} Do you want to delete the abandoned certificate automatic update (please delete) [${Red}Y${Font}${Green}/N]? ${Font}"
            read -r remove_acme_cron_update_fq
            case $remove_acme_cron_update_fq in
            [nN][oO] | [nN]) ;;
            *)
                sed -i "/ssl_update.sh/d" ${crontab_file}
                rm -rf ${ssl_update_file}
                judge "Delete the abandoned certificate automatic update"
                ;;

            esac
        else
            echo -e "\n"
            log_echo "${OK} ${Green} The new version has automatically set the certificate automatic update ${Font}"
            # log_echo "${GreenBG} 是否设置证书自动更新 (新版本无需设置) [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            # read -r acme_cron_update_fq
            # case $acme_cron_update_fq in
            # [yY][eE][sS] | [yY])
            #     # if [[ "${ssl_self}" != "on" ]]; then
            #     #     wget -N -P ${idleleo_dir} --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/ssl_update.sh && chmod +x ${ssl_update_file}
            #     #     if [[ $(crontab -l | grep -c "acme.sh") -lt 1 ]]; then
            #     #         echo "0 3 15 * * bash ${ssl_update_file}" >>${crontab_file}
            #     #     else
            #     #         sed -i "/acme.sh/c 0 3 15 * * bash ${ssl_update_file}" ${crontab_file}
            #     #     fi
            #     #     judge "Set certificate automatic update"
            #     # else
            #     #     log_echo "${Error} ${RedBG} Custom certificates do not support this operation! ${Font}"
            #     # fi
            #     log_echo "${Error} ${RedBG} The new version should not be used! ${Font}"
            #     ;;
            # *) ;;
            # esac
        fi
    else
        log_echo "${Error} ${RedBG} The current mode does not support this operation! ${Font}"
    fi
}

check_cert_status() {
    if [[ ${tls_mode} == "TLS" ]]; then
        host="$(info_extraction host)"
        if [[ -d "$HOME/.acme.sh/${host}_ecc" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.key" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.cer" ]]; then
            modifyTime=$(stat "$HOME/.acme.sh/${host}_ecc/${host}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')
            modifyTime=$(date +%s -d "${modifyTime}")
            currentTime=$(date +%s)
            ((stampDiff = currentTime - modifyTime))
            ((days = stampDiff / 86400))
            ((remainingDays = 90 - days))
            tlsStatus=${remainingDays}
            [[ ${remainingDays} -le 0 ]] && tlsStatus="${Red}Expired${Font}"
            echo -e "\n"
            log_echo "${Green} Certificate generation date: $(date -d "@${modifyTime}" +"%F %H:%M:%S")${Font}"
            log_echo "${Green} Certificate generation days: ${days}${Font}"
            log_echo "${Green} Certificate remaining days: ${tlsStatus}${Font}"
            echo -e "\n"
            if [[ ${remainingDays} -le 0 ]]; then
                echo -e "\n"
                log_echo "${Warning} ${YellowBG} Do you want to update the certificate immediately [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r cert_update_manuel_fq
                case $cert_update_manuel_fq in
                [yY][eE][sS] | [yY])
                    systemctl stop xray
                    judge "Xray stop"
                    cert_update_manuel
                    ;;
                *) ;;
                esac
            fi
        else
            log_echo "${Error} ${RedBG} The certificate issuance tool does not exist, please confirm whether the certificate is issued by the script! ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} The current mode does not support this operation! ${Font}"
    fi
}

cert_update_manuel() {
    if [[ ${tls_mode} == "TLS" ]]; then
        if [[ -f "${amce_sh_file}" ]]; then
            "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
        else
            log_echo "${Error} ${RedBG} The certificate issuance tool does not exist, please confirm whether the certificate is issued by the script! ${Font}"
        fi
        host="$(info_extraction host)"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${host}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
        judge "Certificate update"
        service_restart
    else
        log_echo "${Error} ${RedBG} The current mode does not support this operation! ${Font}"
    fi
}

set_fail2ban() {
    mf_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/fail2ban_manager.sh"
    if [ ! -f "${idleleo_dir}/fail2ban_manager.sh" ]; then
        log_echo "${Info} ${Green} The local file fail2ban_manager.sh does not exist, downloading... ${Font}"
        curl -sL "$mf_remote_url" -o "${idleleo_dir}/fail2ban_manager.sh"
        if [ $? -ne 0 ]; then
            log_echo "${Error} ${RedBG} Download failed, please manually download and install the new version ${Font}"
            return 1
        fi
        chmod +x "${idleleo_dir}/fail2ban_manager.sh"
    fi
    source "${idleleo_dir}/fail2ban_manager.sh"
}

clean_logs() {
    local cron_file logrotate_config
    echo -e "\n"
    log_echo "${Green} Detected log file size as follows: ${Font}"
    log_echo "${Green}$(du -sh /var/log/xray ${nginx_dir}/logs)${Font}"
    timeout "Clearing immediately!"
    for i in $(find /var/log/xray/ ${nginx_dir}/logs -name "*.log"); do cat /dev/null >"$i"; done
    judge "Log cleaning"
    
    #以下为兼容代码，1个大版本后删除
    if [[ "${ID}" == "centos" ]]; then
        cron_file="/var/spool/cron/root"
    else
        cron_file="/var/spool/cron/crontabs/root"
    fi

    if [[ $(grep -c "find /var/log/xray/ /etc/nginx/logs -name" "$cron_file") -ne '0' ]]; then
        log_echo "${Warning} ${YellowBG} The old version of automatic log cleaning task already exists ${Font}"
        log_echo "${GreenBG} Do you want to delete the old version of automatic log cleaning task [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r delete_task
        case $delete_task in
        [nN][oO] | [nN])
            log_echo "${OK} ${Green} Keep the existing automatic log cleaning task ${Font}"
            return
            ;;
        *)
            sed -i "/find \/var\/log\/xray\/ \/etc\/nginx\/logs -name/d" "$cron_file"
            judge "Delete the old version of automatic log cleaning task"
            ;;
        esac
    fi
    #兼容代码结束

    echo -e "\n"
    log_echo "${GreenBG} Do you want to set up automatic log cleaning [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r auto_clean_logs_fq
    case $auto_clean_logs_fq in
    [nN][oO] | [nN])
        timeout "Clear screen!"
        clear
        ;;
    *)
        log_echo "${OK} ${Green} Logs will be automatically cleared at 04:00 every Wednesday ${Font}"

        logrotate_config="/etc/logrotate.d/xray_log_cleanup"

        if [[ -f "$logrotate_config" ]]; then
            log_echo "${Warning} ${YellowBG} Automatic log cleaning task already exists ${Font}"
            log_echo "${GreenBG} Do you want to delete the existing automatic log cleaning task [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r delete_task
            case $delete_task in
            [yY][eE][sS] | [yY])
                rm -f "$logrotate_config"
                judge "Delete automatic log cleaning task"
                ;;
            *)
                log_echo "${OK} ${Green} Keep the existing automatic log cleaning task ${Font}"
                return
                ;;
            esac
        fi

        echo "/var/log/xray/*.log ${nginx_dir}/logs/*.log {" > "$logrotate_config"
        echo "    weekly" >> "$logrotate_config"
        echo "    rotate 3" >> "$logrotate_config"
        echo "    compress" >> "$logrotate_config"
        echo "    missingok" >> "$logrotate_config"
        echo "    notifempty" >> "$logrotate_config"
        echo "    create 640 nobody nogroup" >> "$logrotate_config"
        echo "}" >> "$logrotate_config"
        
        judge "Set up automatic log cleaning"
        ;;
    esac
}

vless_qr_config_tls_ws() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${domain}",
    "ip_version": "${ip_version}",
    "port": ${port},
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "tls": "TLS",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "ws/gRPC",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}",
    "nginx_build_version": "${nginx_build_version}"
}
EOF
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
}

vless_qr_config_reality() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "port": ${port},
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "raw",
    "tls": "Reality",
    "target": "${target}",
    "serverNames":"${serverNames}",
    "privateKey":"${privateKey}",
    "publicKey":"${publicKey}",
    "shortIds":"${shortIds}",
    "reality_add_nginx": "${reality_add_nginx}",
    "reality_add_more": "${reality_add_more}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "ws_path": "${artpath}",
    "grpc_serviceName": "${artserviceName}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}"
}
EOF
    if [[ ${reality_add_nginx} == "on" ]]; then
        jq --arg nginx_build_version "${nginx_build_version}" '. + {"nginx_build_version": $nginx_build_version}' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
    fi
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
}

vless_qr_config_ws_only() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "tls": "None",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "ws/gRPC",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}"
}
EOF
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
}

vless_urlquote() {
    [[ $# = 0 ]] && return 1
    echo "import urllib.request;print(urllib.request.quote('$1'));" | python3
}

vless_qr_link_image() {
    if [[ ${tls_mode} == "TLS" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=ws#$(vless_urlquote $(info_extraction host))+ws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=grpc#$(vless_urlquote $(info_extraction host))+gRPC%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=ws#$(vless_urlquote $(info_extraction host))+ws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=grpc#$(vless_urlquote $(info_extraction host))+gRPC%E5%8D%8F%E8%AE%AE"
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        vless_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?security=reality&flow=xtls-rprx-vision&fp=chrome&pbk=$(info_extraction publicKey)&sni=$(info_extraction serverNames)&target=$(info_extraction target)&sid=$(info_extraction shortIds)#$(vless_urlquote $(info_extraction host))+Reality%E5%8D%8F%E8%AE%AE"
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACgrpc%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACgrpc%E5%8D%8F%E8%AE%AE"
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACgrpc%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ACgrpc%E5%8D%8F%E8%AE%AE"
        fi
    fi
    {
        echo -e "\n"
        log_echo "${Red} —————————————— Xray configuration sharing —————————————— ${Font}"
        if [[ ${tls_mode} == "Reality" ]]; then
            log_echo "${Red} URL sharing link:${Font} ${vless_link}"
            log_echo "$Red 二维码: $Font"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo -e "\n"
        fi
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            log_echo "${Red} ws URL sharing link:${Font} ${vless_ws_link}"
            log_echo "$Red 二维码: $Font"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo -e "\n"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            log_echo "${Red} gRPC URL sharing link:${Font} ${vless_grpc_link}"
            log_echo "$Red 二维码: $Font"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo -e "\n"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            log_echo "${Red} ws URL sharing link:${Font} ${vless_ws_link}"
            log_echo "$Red 二维码: $Font"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo -e "\n"
            log_echo "${Red} gRPC URL sharing link:${Font} ${vless_grpc_link}"
            log_echo "$Red 二维码: $Font"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo -e "\n"
        fi
    } >>"${xray_info_file}"
}

vless_link_image_choice() {
    echo -e "\n"
    log_echo "${GreenBG} Generate sharing link: ${Font}"
    vless_qr_link_image
}

info_extraction() {
    echo ${info_extraction_all} | jq -r ".$1"
    [[ 0 -ne $? ]] && read_config_status=0
}

basic_information() {
    {
        echo -e "\n"
        case ${shell_mode} in
        Nginx+ws+TLS)
            log_echo "${OK} ${GreenBG} Xray+Nginx+ws+TLS installation successful ${Font}"
            ;;
        Nginx+gRPC+TLS)
            log_echo "${OK} ${GreenBG} Xray+Nginx+grpc+TLS installation successful ${Font}"
            ;;
        Nginx+ws+gRPC+TLS)
            log_echo "${OK} ${GreenBG} Xray+Nginx+ws+gRPC+TLS installation successful ${Font}"
            ;;
        Reality)
            log_echo "${OK} ${GreenBG} Xray+Reality installation successful ${Font}"
            ;;
        Reality+ws)
            log_echo "${OK} ${GreenBG} Xray+Reality+ws installation successful ${Font}"
            ;;
        Reality+gRPC)
            log_echo "${OK} ${GreenBG} Xray+Reality+gRPC installation successful ${Font}"
            ;;
        Reality+ws+gRPC)
            log_echo "${OK} ${GreenBG} Xray+Reality+ws+gRPC installation successful ${Font}"
            ;;
        ws ONLY)
            log_echo "${OK} ${GreenBG} ws ONLY installation successful ${Font}"
            ;;
        gRPC ONLY)
            log_echo "${OK} ${GreenBG} gRPC ONLY installation successful ${Font}"
            ;;
        ws+gRPC ONLY)
            log_echo "${OK} ${GreenBG} ws+gRPC ONLY installation successful ${Font}"
            ;;
        esac
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} VLESS currently the sharing link specification is experimental, please judge whether it is applicable by yourself ${Font}"
        echo -e "\n"
        log_echo "${Red} —————————————— Xray configuration information —————————————— ${Font}"
        log_echo "${Red} Host (host):${Font} $(info_extraction host) "
        if [[ ${tls_mode} == "None" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                log_echo "${Red} ws Port (port):${Font} $(info_extraction ws_port) "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                log_echo "${Red} gRPC Port (port):${Font} $(info_extraction grpc_port) "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                log_echo "${Red} ws Port (port):${Font} $(info_extraction ws_port) "
                log_echo "${Red} gRPC Port (port):${Font} $(info_extraction grpc_port) "
            fi
        else
            log_echo "${Red} Port (port):${Font} $(info_extraction port) "
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                log_echo "${Red} Xray ws Port (inbound_port):${Font} $(info_extraction ws_port) "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                log_echo "${Red} Xray gRPC Port (inbound_port):${Font} $(info_extraction grpc_port) "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                log_echo "${Red} Xray ws Port (inbound_port):${Font} $(info_extraction ws_port) "
                log_echo "${Red} Xray gRPC Port (inbound_port):${Font} $(info_extraction grpc_port) "
            fi
        fi
        log_echo "${Red} UUIDv5 mapping string:${Font} $(info_extraction idc)"
        log_echo "${Red} User ID (UUID):${Font} $(info_extraction id)"

        log_echo "${Red} Encryption (encryption):${Font} None "
        log_echo "${Red} Transfer protocol (network):${Font} $(info_extraction net) "
        log_echo "${Red} Underlying transfer security (tls):${Font} $(info_extraction tls) "  
        if [[ ${tls_mode} != "Reality" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                log_echo "${Red} Path (path do not omit /):${Font} /$(info_extraction path) "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                log_echo "${Red} serviceName (do not add /):${Font} $(info_extraction serviceName) "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                log_echo "${Red} Path (path do not omit /):${Font} /$(info_extraction path) "
                log_echo "${Red} serviceName (do not add /):${Font} $(info_extraction serviceName) "
            fi
        else
            log_echo "${Red} Flow control (flow):${Font} xtls-rprx-vision "
            log_echo "${Red} target:${Font} $(info_extraction target) "
            log_echo "${Red} serverNames:${Font} $(info_extraction serverNames) "
            log_echo "${Red} privateKey:${Font} $(info_extraction privateKey) "
            log_echo "${Red} publicKey:${Font} $(info_extraction publicKey) "
            log_echo "${Red} shortIds:${Font} $(info_extraction shortIds) "
            if [[ "$reality_add_more" == "on" ]]; then
                if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                    log_echo "${Red} ws Port (port):${Font} $(info_extraction ws_port) "
                    log_echo "${Red} ws Path (do not omit /):${Font} /$(info_extraction ws_path) "
                elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                    log_echo "${Red} gRPC Port (port):${Font} $(info_extraction grpc_port) "
                    log_echo "${Red} gRPC serviceName (do not add /):${Font} $(info_extraction grpc_serviceName) "
                elif [[ ${ws_grpc_mode} == "all" ]]; then
                    log_echo "${Red} ws Port (port):${Font} $(info_extraction ws_port) "
                    log_echo "${Red} ws Path (do not omit /):${Font} /$(info_extraction ws_path) "
                    log_echo "${Red} gRPC Port (port):${Font} $(info_extraction grpc_port) "
                    log_echo "${Red} gRPC serviceName (do not add /):${Font} $(info_extraction grpc_serviceName) "
                fi
            fi
        fi
    } >"${xray_info_file}"
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    cd $HOME
    echo -e "\n"
    log_echo "${GreenBG} About to apply for the certificate, support for using custom certificates ${Font}"
    log_echo "${Green} If you want to use a custom certificate, please follow the steps:  ${Font}"
    log_echo " 1. Rename the certificate file: private key (xray.key), certificate (xray.crt)"
    log_echo " 2. Put the renamed certificate file into the ${ssl_chainpath} directory and then run the script"
    log_echo " 3. Rerun the script"
    log_echo "${GreenBG} Do you want to continue [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r ssl_continue
    case $ssl_continue in
    [nN][oO] | [nN])
        exit 0
        ;;
    *)
        if [[ -f "${ssl_chainpath}/xray.key" && -f "${ssl_chainpath}/xray.crt" ]] && [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            log_echo "${GreenBG} All certificate files already exist, do you want to keep them [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r ssl_delete_1
            case $ssl_delete_1 in
            [nN][oO] | [nN])
                delete_tls_key_and_crt
                rm -rf ${ssl_chainpath}/*
                log_echo "${OK} ${GreenBG} Deleted ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -fR nobody:nogroup ${ssl_chainpath}/*
                judge "Certificate application"
                ;;
            esac
        elif [[ -f "${ssl_chainpath}/xray.key" || -f "${ssl_chainpath}/xray.crt" ]] && [[ ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            log_echo "${GreenBG} Certificate file already exists, do you want to keep it [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r ssl_delete_2
            case $ssl_delete_2 in
            [nN][oO] | [nN])
                rm -rf ${ssl_chainpath}/*
                log_echo "${OK} ${GreenBG} Deleted ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -fR nobody:nogroup ${ssl_chainpath}/*
                judge "Certificate application"
                ssl_self="on"
                ;;
            esac
        elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] && [[ ! -f "${ssl_chainpath}/xray.key" || ! -f "${ssl_chainpath}/xray.crt" ]]; then
            log_echo "${GreenBG} Certificate issuance residual files already exist, do you want to keep them [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r ssl_delete_3
            case $ssl_delete_3 in
            [nN][oO] | [nN])
                delete_tls_key_and_crt
                log_echo "${OK} ${GreenBG} Deleted ${Font}"
                ssl_install
                acme
                ;;
            *)
                "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
                chown -fR nobody:nogroup ${ssl_chainpath}/*
                judge "Certificate application"
                ;;
            esac
        else
            ssl_install
            acme
        fi
        ;;
    esac
}

nginx_systemd() {
    cat >${nginx_systemd_file} <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=${nginx_dir}/logs/nginx.pid
ExecStartPre=${nginx_dir}/sbin/nginx -t
ExecStart=${nginx_dir}/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=${nginx_dir}/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd ServerFile addition"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "${nginx_conf}" ]] && [[ ${tls_mode} == "TLS" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} Please select the supported TLS version (default:2): ${Font}"
        log_echo "${GreenBG} It is recommended to choose TLS1.3 only (secure mode) ${Font}"
        echo -e "1: TLS1.2 and TLS1.3 (compatibility mode)"
        echo -e "${Red}2${Font}: TLS1.3 only (secure mode)"
        local choose_tls
        read_optimize "Enter: " "choose_tls" 2 1 2 "Please enter a valid number"
        if [[ ${choose_tls} == 1 ]]; then
            # if [[ ${tls_mode} == "TLS" ]]; then
            #     sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.2 TLSv1.3;/" $nginx_conf
            # else
            #     log_echo "${Error} ${RedBG} Reality only uses TLS1.3, please choose TLS1.3 only (secure mode)! ${Font}"
            #     tls_type
            # fi
            # sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.2 TLSv1.3;/" $nginx_conf
            # log_echo "${OK} ${GreenBG} Switched to TLS1.2 and TLS1.3 ${Font}"
            log_echo "${Error} ${RedBG} From version 2.2.1, due to the启用 of h3, only TLS1.3 is supported, please choose TLS1.3 only (secure mode)! ${Font}"
            tls_type
        else
            # if [[ ${tls_mode} == "TLS" ]]; then
            #     sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" $nginx_conf
            # ## else
            #     ##sed -i "s/^\( *\)\"minVersion\".*/\1\"minVersion\": \"1.3\",/" ${xray_conf}
            # fi
            sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" $nginx_conf
            log_echo "${OK} ${GreenBG} Switched to TLS1.3 only ${Font}"
        fi
        # if [[ ${tls_mode} == "TLS" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl restart nginx && judge "Nginx restart"
        # elif [[ ${tls_mode} == "Reality" ]]; then
        systemctl restart xray
        judge "Xray restart"
        # fi
    else
        log_echo "${Error} ${RedBG} Nginx/configuration file does not exist or the current mode does not support ${Font}"
    fi
}

reset_vless_qr_config() {
    basic_information
    vless_qr_link_image
    show_information
}

reset_UUID() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        UUID_set
        modify_UUID
        jq --arg uuid "${UUID}" \
           --arg uuid5_char "${UUID5_char}" \
           '.id = $uuid | .idc = $uuid5_char' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        service_restart
        reset_vless_qr_config
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

reset_port() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            read_optimize "Enter the connection port (default value:443):" "port" 443 0 65535 "Enter a value between 0-65535!"
            modify_nginx_port
            jq --argjson port "${port}" '.port = $port' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            log_echo "${Green} Connection port number: ${port} ${Font}"
        elif [[ ${tls_mode} == "Reality" ]]; then
            read_optimize "Enter the connection port (default value:443):" "port" 443 0 65535 "Enter a value between 0-65535!"
            xport=$((RANDOM % 1000 + 20000))
            gport=$((RANDOM % 1000 + 30000))
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                read_optimize "Enter the ws inbound_port:" "xport" "NULL" 0 65535 "Enter a value between 0-65535!"
                port_exist_check "${xport}"
                gport=$((RANDOM % 1000 + 30000))
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${ws_grpc_mode} == "onlygrpc" ]]; then
                read_optimize "Enter the gRPC inbound_port:" "gport" "NULL" 0 65535 "Enter a value between 0-65535!"
                port_exist_check "${gport}"
                xport=$((RANDOM % 1000 + 20000))
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                read_optimize "Enter the ws inbound_port:" "xport" "NULL" 0 65535 "Enter a value between 0-65535!"
                read_optimize "Enter the gRPC inbound_port:" "gport" "NULL" 0 65535 "Enter a value between 0-65535!"
                port_exist_check "${xport}"
                port_exist_check "${gport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            fi
            jq --argjson port "$port" \
               --argjson ws_port "$xport" \
               --argjson grpc_port "$gport" \
               '.port = $port | .ws_port = $ws_port | .grpc_port = $grpc_port' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            modify_inbound_port
            [[ ${reality_add_nginx} == "on" ]] && modify_nginx_port
        elif [[ ${tls_mode} == "None" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                read_optimize "Enter the ws inbound_port:" "xport" "NULL" 0 65535 "Enter a value between 0-65535!"
                port_exist_check "${xport}"
                gport=$((RANDOM % 1000 + 30000))
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                read_optimize "Enter the gRPC inbound_port:" "gport" "NULL" 0 65535 "Enter a value between 0-65535!"
                port_exist_check "${gport}"
                xport=$((RANDOM % 1000 + 20000))
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                read_optimize "Enter the ws inbound_port:" "xport" "NULL" 0 65535 "Enter a value between 0-65535!"
                read_optimize "Enter the gRPC inbound_port:" "gport" "NULL" 0 65535 "Enter a value between 0-65535!"
                port_exist_check "${xport}"
                port_exist_check "${gport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            fi
            jq --argjson ws_port "$xport" \
               --argjson grpc_port "$gport" \
               '.ws_port = ($ws_port | .grpc_port = $grpc_port' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            modify_inbound_port
        fi
        firewall_set
        service_restart
        reset_vless_qr_config
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

reset_target() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} == "Reality" ]]; then
        target_reset=1
        serverNames=$(info_extraction serverNames)
        nginx_reality_serverNames_del
        target_set
        serverNames_set
        modify_target_serverNames
        if [[ ${reality_add_nginx} == "on" ]]; then
            nginx_reality_serverNames_add
        fi
        jq --arg target "${target}" \
           --arg serverNames "${serverNames}" \
           '.target = $target | .serverNames = $serverNames' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        service_restart
        reset_vless_qr_config
    elif [[ ${tls_mode} != "Reality" ]]; then
        log_echo "${Warning} ${YellowBG} This mode does not support modifying target! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

show_user() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} About to display the user, only one can be displayed at a time ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            log_echo "${GreenBG} Please select the protocol used by the displayed user ws/gRPC ${Font}"
            echo -e "${Red}1${Font}: ws (default)"
            echo "2: gRPC"
            local choose_user_prot
            read_optimize "Enter: " "choose_user_prot" 1 1 2 "Please enter a valid number"
            choose_user_prot=$((choose_user_prot - 1))
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_prot=0
        fi
        echo -e "\n"
        log_echo "${GreenBG} Please select the user number to display: ${Font}"
        jq -r -c .inbounds[${choose_user_prot}].settings.clients[].email ${xray_conf} | awk '{print NR""": "$0}'
        local show_user_index
        read_optimize "Enter: " "show_user_index" "NULL"
        if [[ $(jq -r '.inbounds['${choose_user_prot}'].settings.clients|length' ${xray_conf}) -lt ${show_user_index} ]] || [[ ${show_user_index} == 0 ]]; then
            log_echo "${Error} ${RedBG} Selection error! ${Font}"
            show_user
        elif [[ ${show_user_index} == 1 ]]; then
            log_echo "${Error} ${RedBG} Please directly select [15] to display the main user in the main menu ${Font}"
            timeout "Back to menu!"
            menu
        elif [[ ${show_user_index} -gt 1 ]]; then
            show_user_index=$((show_user_index - 1))
            user_email=$(jq -r -c '.inbounds['${choose_user_prot}'].settings.clients['${show_user_index}'].email' ${xray_conf})
            user_id=$(jq -r -c '.inbounds['${choose_user_prot}'].settings.clients['${show_user_index}'].id' ${xray_conf})
        elif [[ ! -z $(echo ${show_user_index} | sed 's/[0-9]//g') ]] || [[ ${show_user_index} == '' ]]; then
            log_echo "${Error} ${RedBG} Selection error! ${Font}"
            show_user
        else
            log_echo "${Warning} ${YellowBG} Please first check whether Xray is correctly installed! ${Font}"
            timeout "Back to menu!"
            menu
        fi
        if [[ ! -z ${user_email} ]] && [[ ! -z ${user_id} ]]; then
            log_echo "${Green} Username: ${user_email} ${Font}"
            log_echo "${Green} UUID: ${user_id} ${Font}"
            if [[ ${tls_mode} == "TLS" ]]; then
                if [[ ${choose_user_prot} == 0 ]]; then
                    user_vless_link="vless://${user_id}@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=ws#$(vless_urlquote $(info_extraction host))+ws%E5%8D%8F%E8%AE%AE"
                elif [[ ${choose_user_prot} == 1 ]]; then
                    user_vless_link="vless://${user_id}@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=grpc#$(vless_urlquote $(info_extraction host))+gRPC%E5%8D%8F%E8%AE%AE"
                fi
            elif [[ ${tls_mode} == "Reality" ]]; then
                user_vless_link="vless://${user_id}@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?security=tls&encryption=none&headerType=none&type=raw&flow=xtls-rprx-vision#$(vless_urlquote $(info_extraction host))+reality%E5%8D%8F%E8%AE%AE"
            fi
            log_echo "${Red} URL sharing link:${Font} ${user_vless_link}"
            echo -n "${user_vless_link}" | qrencode -o - -t utf8
        fi
        echo -e "\n"
        log_echo "${GreenBG} Do you want to continue displaying users [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
        read -r show_user_continue
        case $show_user_continue in
        [yY][eE][sS] | [yY])
            show_user
            ;;
        *) ;;
        esac
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} This mode does not support deleting users! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

add_user() {
    local choose_user_prot
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        service_stop
        echo -e "\n"
        log_echo "${GreenBG} About to add a user, only one can be added at a time ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            log_echo "${GreenBG} Please select the protocol used by the added user ws/gRPC ${Font}"
            echo -e "${Red}1${Font}: ws (default)"
            echo "2: gRPC"
            local choose_user_prot
            read_optimize "Enter: " "choose_user_prot" 1 1 2 "Please enter a valid number"
            choose_user_prot=$((choose_user_prot - 1))
            reality_user_more=""
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_prot=0
            reality_user_more="\"flow\":\"xtls-rprx-vision\","
        fi
        email_set
        UUID_set
        jq --argjson choose_user_prot "${choose_user_prot}" \
           --arg UUID "${UUID}" \
           --arg reality_user_more "${reality_user_more}" \
           --arg custom_email "${custom_email}" \
           '.inbounds[$choose_user_prot].settings.clients += [
               {"id": $UUID} +
               if $reality_user_more != "" then ($reality_user_more | fromjson) else {} end +
               {"level": 0, "email": $custom_email}
           ]' "${xray_conf}" > "${xray_conf}.tmp"
        judge "Add user"
        mv "${xray_conf}.tmp" "${xray_conf}"
        jq ". += {\"multi_user\": \"yes\"}" ${xray_qr_config_file} > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        echo -e "\n"
        log_echo "${GreenBG} Do you want to continue adding users [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
        read -r add_user_continue
        case $add_user_continue in
        [yY][eE][sS] | [yY])
            add_user
            ;;
        *) ;;
        esac
        service_start
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} This mode does not support adding users! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

remove_user() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        service_stop
        echo -e "\n"
        log_echo "${GreenBG} About to delete a user, only one can be deleted at a time ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            log_echo "${GreenBG} Please select the protocol used by the deleted user ws/gRPC ${Font}"
            echo -e "${Red}1${Font}: ws (default)"
            echo "2: gRPC"
            local choose_user_prot
            read_optimize "Enter: " "choose_user_prot" 1 1 2 "Please enter a valid number"
            choose_user_prot=$((choose_user_prot - 1))
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_prot=0
        fi
        echo -e "\n"
        log_echo "${GreenBG} Please select the user number to delete ${Font}"
        jq -r -c .inbounds[${choose_user_prot}].settings.clients[].email ${xray_conf} | awk '{print NR""": "$0}'
        local del_user_index
        read_optimize "Enter: " "del_user_index" "NULL"
        if [[ $(jq -r '.inbounds['${choose_user_prot}'].settings.clients|length' ${xray_conf}) -lt ${del_user_index} ]] || [[ ${show_user_index} == 0 ]]; then
            log_echo "${Error} ${RedBG} Selection error! ${Font}"
            remove_user
        elif [[ ${del_user_index} == 1 ]]; then
            echo -e "\n"
            log_echo "${Error} ${RedBG} Please directly modify the UUID/Email of the main user in the main menu! ${Font}"
            timeout "Back to menu!"
            menu
        elif [[ ${del_user_index} -gt 1 ]]; then
            del_user_index=$((del_user_index - 1))
            jq --argjson choose_user_prot "${choose_user_prot}" --argjson del_user_index "${del_user_index}" \
               'del(.inbounds[$choose_user_prot].settings.clients[$del_user_index])' ${xray_conf} > "${xray_conf}.tmp"
            judge "Delete user"
            mv "${xray_conf}.tmp" "${xray_conf}"
            echo -e "\n"
            log_echo "${GreenBG} Do you want to continue deleting users [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
            read -r remove_user_continue
            case $remove_user_continue in
            [yY][eE][sS] | [yY])
                remove_user
                ;;
            *) ;;
            esac
        elif [[ ! -z $(echo ${del_user_index} | sed 's/[0-9]//g') ]] || [[ ${del_user_index} == '' ]]; then
            log_echo "${Error} ${RedBG} Selection error! ${Font}"
            remove_user
        else
            log_echo "${Warning} ${YellowBG} Please first check whether Xray is correctly installed! ${Font}"
            timeout "Back to menu!"
            menu
        fi
        service_start
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} This mode does not support deleting users! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

show_access_log() {
    [[ -f "${xray_access_log}" ]] && tail -f ${xray_access_log} || log_echo "${Error} ${RedBG} Log file does not exist! ${Font}"
}

show_error_log() {
    [[ -f "${xray_error_log}" ]] && tail -f ${xray_error_log} || log_echo "${Error} ${RedBG} Log file does not exist! ${Font}"
}

xray_status_add() {
    if [[ -f "${xray_conf}" ]]; then
        if [[ $(jq -r .stats ${xray_conf}) != null ]]; then
            echo -e "\n"
            log_echo "${GreenBG} Xray traffic statistics have already been configured ${Font}"
            log_echo "${GreenBG} Do you want to disable this feature [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop
                jq "del(.api)|del(.stats)|del(.policy)" ${xray_conf} > "${xray_conf}.tmp"
                judge "Disable Xray traffic statistics"
                mv "${xray_conf}.tmp" "${xray_conf}"
                service_start
                [[ -f "${xray_status_conf}" ]] && rm -rf ${xray_status_conf}
                ;;
            *) ;;
            esac
        else
            echo -e "\n"
            log_echo "${GreenBG} Xray traffic statistics require the use of API ${Font}"
            log_echo "${GreenBG} This may affect the performance of Xray ${Font}"
            log_echo "${GreenBG} Do you want to continue [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop
                wget -nc --no-check-certificate "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/status_config.json" -O ${xray_status_conf}
                local status_config
                status_config=$(jq -c . "${xray_status_conf}")
                jq --argjson status_config "${status_config}" \
                   '. += $status_config' "${xray_conf}" > "${xray_conf}.tmp"
                judge "Set Xray traffic statistics"
                mv "${xray_conf}.tmp" "${xray_conf}"
                service_start
                ;;
            *) ;;
            esac
        fi
    else
        log_echo "${Warning} ${YellowBG} Please install Xray first! ${Font}"
    fi
}

bbr_boost_sh() {
    if [[ -f "${idleleo_dir}/tcp.sh" ]]; then
        cd ${idleleo_dir} && chmod +x ./tcp.sh && ./tcp.sh
    else
        wget -N --no-check-certificate -P ${idleleo_dir} "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x ${idleleo_dir}/tcp.sh && ${idleleo_dir}/tcp.sh
    fi
}

uninstall_all() {
    stop_service_all
    if [[ -f "${xray_bin_dir}/xray" ]]; then
        systemctl disable xray
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
        [[ -d "${xray_conf_dir}" ]] && rm -rf ${xray_conf_dir}
        if [[ -f "${xray_qr_config_file}" ]]; then
            jq -r 'del(.xray_version)' ${xray_qr_config_file} > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        fi
        log_echo "${OK} ${GreenBG} Xray has been uninstalled ${Font}"
    fi
    if [[ -d "${nginx_dir}" ]]; then
        log_echo "${GreenBG} Do you want to uninstall Nginx [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            systemctl disable nginx
            rm -rf ${nginx_dir}
            rm -rf ${nginx_conf_dir}/*
            [[ -f "${nginx_systemd_file}" ]] && rm -rf ${nginx_systemd_file}
            if [[ -f "${xray_qr_config_file}" ]]; then
                jq 'del(.nginx_build_version)' ${xray_qr_config_file} > "${xray_qr_config_file}.tmp"
                mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            fi
            log_echo "${OK} ${GreenBG} Nginx has been uninstalled ${Font}"
            ;;
        *) ;;
        esac
    fi
    log_echo "${GreenBG} Do you want to delete all script files [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r remove_all_idleleo_file_fq
    case $remove_all_idleleo_file_fq in
    [yY][eE][sS] | [yY])
        rm -rf ${idleleo_commend_file}
        rm -rf ${idleleo_dir}
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} All files have been deleted ${Font}"
        log_echo "${GreenBG} ヾ(￣▽￣) Sayonara~ ${Font}"
        exit 0
        ;;
    *)
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} The script files have been kept (including SSL certificates, etc.) ${Font}"
        ;;
    esac
    if [[ -f "${xray_qr_config_file}" ]]; then
        log_echo "${GreenBG} Do you want to keep the configuration file [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r remove_config_fq
        case $remove_config_fq in
        [yY][eE][sS] | [yY])
            log_echo "${OK} ${GreenBG} The configuration file has been kept ${Font}"
            ;;
        *)
            rm -rf ${xray_qr_config_file}
            log_echo "${OK} ${GreenBG} The configuration file has been deleted ${Font}"
            ;;
        esac
    fi
}

delete_tls_key_and_crt() {
    [[ -f "$HOME/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d "$HOME/.acme.sh" ]] && rm -rf "$HOME/.acme.sh"
    log_echo "${OK} ${GreenBG} All certificate legacy files have been cleared ${Font}"
}

timeout() {
    timeout=0
    timeout_str=""
    while [[ ${timeout} -le 30 ]]; do
        let timeout++
        timeout_str+="#"
    done
    let timeout=timeout+5
    while [[ ${timeout} -gt 0 ]]; do
        let timeout--
        if [[ ${timeout} -gt 25 ]]; then
            let timeout_color=32
            let timeout_bg=42
            timeout_index="3"
        elif [[ ${timeout} -gt 15 ]]; then
            let timeout_color=33
            let timeout_bg=43
            timeout_index="2"
        elif [[ ${timeout} -gt 5 ]]; then
            let timeout_color=31
            let timeout_bg=41
            timeout_index="1"
        else
            timeout_index="0"
        fi
        printf "${Warning} ${GreenBG} %d seconds later will$1 ${Font} \033[${timeout_color};${timeout_bg}m%-s\033[0m \033[${timeout_color}m%d\033[0m \r" "$timeout_index" "$timeout_str" "$timeout_index"
        sleep 0.1
        timeout_str=${timeout_str%?}
        [[ ${timeout} -eq 0 ]] && printf "\n"
    done
}

judge_mode() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        ws_grpc_mode=$(info_extraction ws_grpc_mode)
        tls_mode=$(info_extraction tls)
        
        case ${ws_grpc_mode} in
            onlyws) shell_mode="ws";;
            onlygRPC) shell_mode="gRPC";;
            all) shell_mode="ws+gRPC";;
            *);;
        esac
        
        case ${tls_mode} in
            TLS)
                shell_mode="Nginx+${shell_mode}+TLS"
                ;;
            Reality)
                reality_add_more=$(info_extraction reality_add_more)
                reality_add_nginx=$(info_extraction reality_add_nginx)
                
                if [[ ${reality_add_nginx} == "on" && ${reality_add_nginx} == "off" ]]; then
                    shell_mode="Reality+${shell_mode}"
                elif [[ ${reality_add_nginx} == "on" && ${reality_add_nginx} == "on" ]]; then
                    shell_mode="Nginx+Reality+${shell_mode}"
                elif [[ ${reality_add_nginx} == "on" && ${reality_add_more} == "off" ]]; then
                    shell_mode="Nginx+Reality"
                else
                    shell_mode="Reality"
                fi
                ;;
            None)
                shell_mode="${shell_mode} ONLY"
                ;;
            *)
                ;;
        esac
        old_tls_mode=${tls_mode}
    fi
}

install_xray_ws_tls() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    basic_optimization
    create_directory
    old_config_exist_check
    domain_check
    ws_grpc_choose
    port_set
    ws_inbound_port_set
    grpc_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    email_set
    UUID_set
    ws_grpc_qr
    vless_qr_config_tls_ws
    stop_service_all
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    nginx_systemd
    nginx_ssl_conf_add
    ssl_judge_and_install
    nginx_conf_add
    nginx_servers_conf_add
    xray_conf_add
    tls_type
    basic_information
    enable_process_systemd
    acme_cron_update
    auto_update
    service_restart
    vless_link_image_choice
    show_information
}

install_xray_reality() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    basic_optimization
    create_directory
    old_config_exist_check
    ip_check
    xray_install
    port_set
    email_set
    UUID_set
    target_set
    serverNames_set
    keys_set
    shortIds_set
    xray_reality_add_more_choose
    ws_grpc_qr
    firewall_set
    stop_service_all
    port_exist_check "${port}"
    reality_nginx_add_fq
    xray_conf_add
    vless_qr_config_reality
    basic_information
    enable_process_systemd
    auto_update
    service_restart
    vless_link_image_choice
    show_information
}

install_xray_ws_only() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    basic_optimization
    create_directory
    old_config_exist_check
    ip_check
    ws_grpc_choose
    ws_inbound_port_set
    grpc_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    email_set
    UUID_set
    ws_grpc_qr
    vless_qr_config_ws_only
    stop_service_all
    xray_install
    port_exist_check "${xport}"
    port_exist_check "${gport}"
    xray_conf_add
    basic_information
    service_restart
    enable_process_systemd
    auto_update
    vless_link_image_choice
    show_information
}

update_sh() {
    ol_version=${shell_online_version}
    echo "${ol_version}" >${shell_version_tmp}
    [[ -z ${ol_version} ]] && log_echo "${Error} ${RedBG} Online version detection failed! ${Font}" && return 1
    echo "${shell_version}" >>${shell_version_tmp}
    newest_version=$(sort -rV ${shell_version_tmp} | head -1)
    oldest_version=$(sort -V ${shell_version_tmp} | head -1)
    version_difference=$(echo "(${newest_version:0:3}-${oldest_version:0:3})>0" | bc)
    if [[ ${shell_version} != ${newest_version} ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            if [[ ${version_difference} == 1 ]]; then
                echo -e "\n"
                log_echo "${Warning} ${YellowBG} There is a new version, but the version span is large, there may be compatibility issues, do you want to update [Y/${Red}N${Font}${YellowBG}]? ${Font}"
            else
                echo -e "\n"
                log_echo "${GreenBG} There is a new version, do you want to update [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            fi
            read -r update_confirm
        else
            [[ -z ${ol_version} ]] && echo "Failed to detect the script's latest version!" >>${log_file} && exit 1
            [[ ${version_difference} == 1 ]] && echo "The script version difference is large, skip the update!" >>${log_file} && exit 1
            update_confirm="YES"
        fi
        case $update_confirm in
        [yY][eE][sS] | [yY])
            [[ -L "${idleleo_commend_file}" ]] && rm -f ${idleleo_commend_file}
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
            [[ -f "${xray_qr_config_file}" ]] && jq --arg shell_version "${shell_version}" '.shell_version = $shell_version' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp" && mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            clear
            log_echo "${OK} ${GreenBG} Update completed ${Font}"
            [[ ${version_difference} == 1 ]] && log_echo "${Warning} ${YellowBG} The script version difference is large, if the service cannot run normally, please uninstall and reinstall! ${Font}"
            ;;
        *) ;;
        esac
    else
        clear
        log_echo "${OK} ${GreenBG} The current version is the latest version ${Font}"
    fi

}

check_file_integrity() {
    if [[ ! -L "${idleleo_commend_file}" ]] && [[ ! -f "${idleleo_dir}/install.sh" ]]; then
        check_system
        pkg_install "bc,jq,wget"
        [[ ! -d "${idleleo_dir}" ]] && mkdir -p ${idleleo_dir}
        [[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p ${idleleo_dir}/tmp
        wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
        judge "Download the latest script"
        ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
        clear
        source "$idleleo"
    fi
}

read_version() {
    shell_online_version="$(check_version shell_online_version)"
    xray_version="$(check_version xray_online_version)"
    nginx_build_version="$(check_version nginx_build_online_version)"
}

maintain() {
    log_echo "${Error} ${RedBG} This option is temporarily not available! ${Font}"
    log_echo "${Error} ${RedBG} $1 ${Font}"
    exit 0
}

list() {
    case $1 in
    '-1' | '--install-tls')
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        ;;
    '-2' | '--install-reality')
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        ;;
    '-3' | '--install-none')
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} This mode is recommended for load balancing, it is not recommended for general use, do you want to install [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            ;;
        *) ;;
        esac
        ;;
    '-4' | '--add-upstream')
        nginx_upstream_server_set
        ;;
    '-5' | '--add-servernames')
        nginx_servernames_server_set
        ;;
    '-au' | '--auto-update')
        auto_update
        ;;
    '-c' | '--clean-logs')
        clean_logs
        ;;
    '-cs' | '--cert-status')
        check_cert_status
        ;;
    '-cu' | '--cert-update')
        cert_update_manuel
        ;;
    '-cau' | '--cert-auto-update')
        acme_cron_update
        ;;
    '-f' | '--set-fail2ban')
        set_fail2ban
        ;;
    '-h' | '--help')
        show_help
        ;;
    '-n' | '--nginx-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        nginx_update
        ;;
    '-p' | '--port-reset')
        reset_port
        ;;
    '--purge' | '--uninstall')
        uninstall_all
        ;;
    '-s' | '-show')
        clear
        basic_information
        vless_qr_link_image
        show_information
        ;;
    '-t' | '--target-reset')
        reset_target
        ;;
    '-tcp' | '--tcp')
        bbr_boost_sh
        ;;
    '-tls' | '--tls')
        tls_type
        ;;
    '-u' | '--update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        update_sh
        ;;
    '-uu' | '--uuid-reset')
        reset_UUID
        ;;
    '-xa' | '--xray-access')
        clear
        show_access_log
        ;;
    '-xe' | '--xray-error')
        clear
        show_error_log
        ;;
    '-x' | '--xray-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        xray_update
        ;;
    *)
        menu
        ;;
    esac
}

show_help() {
    echo "usage: idleleo [OPTION]"
    echo
    echo 'OPTION:'
    echo '  -1, --install-tls           Install Xray (Nginx+ws/gRPC+TLS)'
    echo '  -2, --install-reality       Install Xray (Nginx+Reality+ws/gRPC)'
    echo '  -3, --install-none          Install Xray (ws/gRPC ONLY)'
    echo '  -4, --add-upstream          Change Nginx load balancing configuration'
    echo '  -5, --add-servernames       Change Nginx serverNames configuration'
    echo '  -au, --auto-update          Set automatic update'
    echo '  -c, --clean-logs            Clear log files'
    echo '  -cs, --cert-status          View certificate status'
    echo '  -cu, --cert-update          Update certificate validity period'
    echo '  -cau, --cert-auto-update    Set automatic certificate update'
    echo '  -f, --set-fail2ban          Set Fail2ban to prevent brute force cracking'
    echo '  -h, --help                  Show help'
    echo '  -n, --nginx-update          Update Nginx'
    echo '  -p, --port-reset            Change port'
    echo '  --purge, --uninstall        Uninstall the script'
    echo '  -s, --show                  Show installation information'
    echo '  -t, --target-reset          Change target'
    echo '  -tcp, --tcp                 Configure TCP acceleration'
    echo '  -tls, --tls                 Modify TLS configuration'
    echo '  -u, --update                Update the script'
    echo '  -uu, --uuid-reset           Change UUIDv5/mapping string'
    echo '  -xa, --xray-access          Show Xray access information'
    echo '  -xe, --xray-error           Show Xray error information'
    echo '  -x, --xray-update           Update Xray'
    exit 0
}

idleleo_commend() {
    if [[ -L "${idleleo_commend_file}" ]] || [[ -f "${idleleo_dir}/install.sh" ]]; then
        ##在线运行与本地脚本比对
        [[ ! -L "${idleleo_commend_file}" ]] && chmod +x ${idleleo_dir}/install.sh && ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
        old_version=$(grep "shell_version=" ${idleleo_dir}/install.sh | head -1 | awk -F '=|"' '{print $3}')
        echo "${old_version}" >${shell_version_tmp}
        echo "${shell_version}" >>${shell_version_tmp}
        oldest_version=$(sort -V ${shell_version_tmp} | head -1)
        version_difference=$(echo "(${shell_version:0:3}-${oldest_version:0:3})>0" | bc)
        if [[ -z ${old_version} ]]; then
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            judge "Download the latest script"
            clear
            source "$idleleo"
        elif [[ ${shell_version} != ${oldest_version} ]]; then
            if [[ ${version_difference} == 1 ]]; then
                log_echo "${Warning} ${YellowBG} The script version difference is large, there may be compatibility issues, do you want to continue [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r update_sh_fq
                case $update_sh_fq in
                [yY][eE][sS] | [yY])
                    rm -rf ${idleleo_dir}/install.sh
                    wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
                    judge "Download the latest script"
                    clear
                    log_echo "${Warning} ${YellowBG} The script version difference is large, if the service cannot run normally, please uninstall and reinstall! ${Font}"
                    echo -e "\n"
                    ;;
                *)
                    source "$idleleo"
                    ;;
                esac
            else
                rm -rf ${idleleo_dir}/install.sh
                wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
                judge "Download the latest script"
                clear
            fi
            source "$idleleo"
        else
            ol_version=${shell_online_version}
            echo "${ol_version}" >${shell_version_tmp}
            [[ -z ${ol_version} ]] && shell_need_update="${Red}[Detection failed!]${Font}"
            echo "${shell_version}" >>${shell_version_tmp}
            newest_version=$(sort -rV ${shell_version_tmp} | head -1)
            if [[ ${shell_version} != ${newest_version} ]]; then
                shell_need_update="${Red}[New version available!]${Font}"
                shell_emoji="${Red}>_<${Font}"
            else
                shell_need_update="${Green}[Latest version]${Font}"
                shell_emoji="${Green}^O^${Font}"
            fi
            if [[ -f "${xray_qr_config_file}" ]]; then
                if [[ "$(info_extraction nginx_build_version)" == "null" ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
                    nginx_need_update="${Green}[Not installed]${Font}"
                elif [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
                    nginx_need_update="${Green}[New version available]${Font}"
                else
                    nginx_need_update="${Green}[Latest version]${Font}"
                fi
                if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ -f "${xray_bin_dir}/xray" ]]; then
                    xray_online_version=$(check_version xray_online_version)
                    ##xray_online_version=$(check_version xray_online_pre_version)
                    if [[ "$(info_extraction xray_version)" == "null" ]]; then
                        xray_need_update="${Green}[Installed] (Version unknown)${Font}"
                    elif [[ ${xray_version} != $(info_extraction xray_version) ]] && [[ $(info_extraction xray_version) != ${xray_online_version} ]]; then
                        xray_need_update="${Red}[New version available!]${Font}"
                        ### xray_need_update="${Red}[Please update immediately!]${Font}"
                    elif [[ ${xray_version} == $(info_extraction xray_version) ]] || [[ $(info_extraction xray_version) == ${xray_online_version} ]]; then
                        if [[ $(info_extraction xray_version) != ${xray_online_version} ]]; then
                            xray_need_update="${Green}[Test version available]${Font}"
                        else
                            xray_need_update="${Green}[Latest version]${Font}"
                        fi
                    fi
                else
                    xray_need_update="${Red}[Not installed]${Font}"
                fi
            else
                nginx_need_update="${Green}[Not installed]${Font}"
                xray_need_update="${Red}[Not installed]${Font}"
            fi
        fi
    fi
}

check_program() {
    if [[ -n $(pgrep nginx) ]]; then
        nignx_status="${Green}Running..${Font}"
    elif [[ ${tls_mode} == "None" ]] || [[ ${reality_add_nginx} == "off" ]]; then
        nignx_status="${Green}No need to test${Font}"
    else
        nignx_status="${Red}Not running${Font}"
    fi
    if [[ -n $(pgrep xray) ]]; then
        xray_status="${Green}Running..${Font}"
    else
        xray_status="${Red}Not running${Font}"
    fi
}

curl_local_connect() {
    curl -Is -o /dev/null -w %{http_code} "https://$1/$2"
}

check_xray_local_connect() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        xray_local_connect_status="${Red}Unable to connect${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            [[ ${ws_grpc_mode} == "onlyws" ]] && [[ $(curl_local_connect $(info_extraction host) $(info_extraction path)) == "400" ]] && xray_local_connect_status="${Green}Local normal${Font}"
            [[ ${ws_grpc_mode} == "onlygrpc" ]] && [[ $(curl_local_connect $(info_extraction host) $(info_extraction serviceName)) == "502" ]] && xray_local_connect_status="${Green}Local normal${Font}"
            [[ ${ws_grpc_mode} == "all" ]] && [[ $(curl_local_connect $(info_extraction host) $(info_extraction serviceName)) == "502" && $(curl_local_connect $(info_extraction host) $(info_extraction path)) == "400" ]] && xray_local_connect_status="${Green}Local normal${Font}"
        elif [[ ${tls_mode} == "Reality" ]]; then
            #[[ $(curl_local_connect $(info_extraction host)) == "302" ]] && xray_local_connect_status="${Green}Local normal${Font}"
            xray_local_connect_status="${Green}No need to test${Font}"
        elif [[ ${tls_mode} == "None" ]]; then
            xray_local_connect_status="${Green}No need to test${Font}"
        fi
    else
        xray_local_connect_status="${Red}Not installed${Font}"
    fi
}

check_online_version_connect() {
    xray_online_version_status=$(curl_local_connect "www.idleleo.com" "api/xray_shell_versions")
    if [[ ${xray_online_version_status} != "200" ]]; then
        if [[ ${xray_online_version_status} == "403" ]]; then
            log_echo "${Error} ${RedBG} The script is under maintenance.. Please try again later! ${Font}"
        else
            log_echo "${Error} ${RedBG} Unable to detect the online version of the required dependencies, please try again later! ${Font}"
        fi
        sleep 0.5
        exit 0
    fi
}

set_language() {
    echo -e "\n"
    log_echo "${GreenBG} 是否需要使用中文版本 [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r language_choice
    case $language_choice in
        [yY][eE][sS] | [yY])

            curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh -o "${idleleo_dir}/install.sh"

            if [ $? -ne 0 ]; then
                log_echo "${Error} ${RedBG} 无法下载英文版 install.sh ${Font}"
                return 1
            fi

            chmod +x "${idleleo_dir}/install-en.sh"

            if [ -L "${idleleo_commend_file}" ]; then
                rm -f "${idleleo_commend_file}"
            fi
            ln -sf "${idleleo_dir}/install.sh" "${idleleo_commend_file}"

            log_echo "${OK} ${Green} 中文版已下载, 可以使用 '${Red}idleleo${Font}${Green}' 命令运行 ${Font}"
            ;;
        *)
            log_echo "${OK} ${Green} 已跳过语言设置 ${Font}"
            ;;
    esac
}

#以下为兼容代码，1个大版本后删除
fix_bugs() {
    local log_cleanup_file_path="/etc/logrotate.d/custom_log_cleanup"   
    if [[ -f "${log_cleanup_file_path}" ]]; then
        echo -e "\n"
        log_echo "${Warning} ${RedBG} Detected a BUG! ${Font}"
        log_echo "${Warning} ${YellowBG} The BUG comes from the wrong setting of automatic log cleaning ${Font}"
        log_echo "${Warning} ${YellowBG} Starting to fix.. ${Font}"
        [[ -f "${nginx_dir}/sbin/nginx" ]] && chown -fR nobody:nogroup "${nginx_dir}/logs"
        chown -fR nobody:nogroup /var/log/xray/
        rm -f "${log_cleanup_file_path}"
        judge "Deleted the wrong configuration file"
        log_echo "${Warning} ${YellowBG} Will re-set automatic log cleaning.. ${Font}"
        bash "${idleleo}" --clean-logs
    fi
}
#兼容代码结束

menu() {
    echo -e "\n"
    log_echo "Xray installation management script ${Red}[${shell_version}]${Font} ${shell_emoji}"
    log_echo "--- authored by hello-yunshu ---"
    log_echo "--- changed by www.idleleo.com ---"
    log_echo "--- https://github.com/hello-yunshu ---"
    echo -e "\n"
    log_echo "Current mode: ${shell_mode}"
    echo -e "\n"

    echo -e "You can use the '${RedW}idleleo${Font}' command to manage the script${Font}\n"

    log_echo "—————————————— ${GreenW}Version detection${Font} ——————————————"
    log_echo "Script:  ${shell_need_update}"
    log_echo "Xray:  ${xray_need_update}"
    log_echo "Nginx: ${nginx_need_update}"
    log_echo "—————————————— ${GreenW}Running status${Font} ——————————————"
    log_echo "Xray:   ${xray_status}"
    log_echo "Nginx:  ${nignx_status}"
    log_echo "Connectivity: ${xray_local_connect_status}"
    echo -e "—————————————— ${GreenW}Upgrade guide${Font} ——————————————"
    echo -e "${Green}0.${Font} Upgrade the script"
    echo -e "${Green}1.${Font} Upgrade Xray"
    echo -e "${Green}2.${Font} Upgrade Nginx"
    echo -e "—————————————— ${GreenW}Language Settings${Font} ——————————————"
    echo -e "${Green}34.${Font} 中文版"
    echo -e "—————————————— ${GreenW}Installation guide${Font} ——————————————"
    echo -e "${Green}3.${Font} Install Xray (Reality+ws/gRPC+Nginx)"
    echo -e "${Green}4.${Font} Install Xray (Nginx+ws/gRPC+TLS)"
    echo -e "${Green}5.${Font} Install Xray (ws/gRPC ONLY)"
    echo -e "—————————————— ${GreenW}Configuration change${Font} ——————————————"
    echo -e "${Green}6.${Font} Change UUIDv5/mapping string"
    echo -e "${Green}7.${Font} Change port"
    echo -e "${Green}8.${Font} Change target"
    echo -e "${Green}9.${Font} Change TLS version"
    echo -e "${Green}10.${Font} Change Nginx load balancing configuration"
    echo -e "${Green}11.${Font} Change Nginx serverNames configuration"
    echo -e "—————————————— ${GreenW}User management${Font} ——————————————"
    echo -e "${Green}12.${Font} View Xray users"
    echo -e "${Green}13.${Font} Add Xray users"
    echo -e "${Green}14.${Font} Delete Xray users"
    echo -e "—————————————— ${GreenW}View information${Font} ——————————————"
    echo -e "${Green}15.${Font} View Xray real-time access log"
    echo -e "${Green}16.${Font} View Xray real-time error log"
    echo -e "${Green}17.${Font} View Xray configuration information"
    echo -e "—————————————— ${GreenW}Service related${Font} ——————————————"
    echo -e "${Green}18.${Font} Restart all services"
    echo -e "${Green}19.${Font} Start all services"
    echo -e "${Green}20.${Font} Stop all services"
    echo -e "${Green}21.${Font} View all services"
    echo -e "—————————————— ${GreenW}Certificate related${Font} ——————————————"
    echo -e "${Green}22.${Font} View certificate status"
    echo -e "${Green}23.${Font} Update certificate validity period"
    echo -e "${Green}24.${Font} Set automatic certificate update"
    echo -e "—————————————— ${GreenW}Other options${Font} ——————————————"
    echo -e "${Green}25.${Font} Configure automatic update"
    echo -e "${Green}26.${Font} Configure TCP acceleration"
    echo -e "${Green}27.${Font} Set Fail2ban to prevent brute force cracking"
    echo -e "${Green}28.${Font} Set Xray traffic statistics"
    echo -e "${Green}29.${Font} Clear log files"
    echo -e "${Green}30.${Font} Test server speed"
    echo -e "—————————————— ${GreenW}Uninstallation guide${Font} ——————————————"
    echo -e "${Green}31.${Font} Uninstall the script"
    echo -e "${Green}32.${Font} Clear certificate files"
    echo -e "${Green}33.${Font} Exit \n"

    local menu_num
    read_optimize "Enter the option: " "menu_num" "NULL" 0 34 "Please enter a number between 0 and 34"
    case $menu_num in
    0)
        update_sh
        source "$idleleo"
        ;;
    1)
        xray_update
        timeout "Clear screen!"
        clear
        source "$idleleo"
        ;;
    2)
        echo -e "\n"
        log_echo "${Red}[Not recommended]${Font} Frequently updating Nginx, please confirm that Nginx needs to be updated! "
        timeout "Start updating!"
        nginx_update
        timeout "Clear screen!"
        clear
        source "$idleleo"
        ;;
    3)
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        source "$idleleo"
        ;;
    4)
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        source "$idleleo"
        ;;
    5)
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} This mode is recommended for load balancing, it is not recommended for general use, do you want to install [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            ;;
        *) ;;
        esac
        source "$idleleo"
        ;;
    6)
        reset_UUID
        judge "Change UUIDv5/mapping string"
        menu
        ;;
    7)
        reset_port
        judge "Change port"
        menu
        ;;
    8)
        reset_target
        judge "Change target"
        menu
        ;;
    9)
        tls_type
        judge "Change TLS version"
        menu
        ;;
    10)
        nginx_upstream_server_set
        timeout "Clear screen!"
        clear
        menu
        ;;
    11)
        nginx_servernames_server_set
        timeout "Clear screen!"
        clear
        menu
        ;;
    12)
        show_user
        timeout "Back to menu!"
        menu
        ;;
    13)
        add_user
        timeout "Back to menu!"
        menu
        ;;
    14)
        remove_user
        timeout "Back to menu!"
        menu
        ;;
    15)
        clear
        show_access_log
        ;;
    16)
        clear
        show_error_log
        ;;
    17)
        clear
        basic_information
        vless_qr_link_image
        show_information
        menu
        ;;
    18)
        service_restart
        timeout "Clear screen!"
        clear
        menu
        ;;
    19)
        service_start
        timeout "Clear screen!"
        clear
        source "$idleleo"
        ;;
    20)
        service_stop
        timeout "Clear screen!"
        clear
        source "$idleleo"
        ;;
    21)
        if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
            systemctl status nginx
        fi
        systemctl status xray
        menu
        ;;
    22)
        check_cert_status
        timeout "Back to menu!"
        menu
        ;;
    23)
        cert_update_manuel
        timeout "Back to menu!"
        menu
        ;;
    24)
        acme_cron_update
        timeout "Clear screen!"
        clear
        menu
        ;;
    25)
        auto_update
        timeout "Clear screen!"
        clear
        menu
        ;;
    26)
        clear
        bbr_boost_sh
        ;;
    27)
        set_fail2ban
        menu
        ;;
    28)
        xray_status_add
        timeout "Back to menu!"
        menu
        ;;
    29)
        clean_logs
        menu
        ;;
    30)
        clear
        bash <(curl -Lso- https://git.io/Jlkmw)
        ;;
    31)
        uninstall_all
        timeout "Clear screen!"
        clear
        source "$idleleo"
        ;;
    32)
        delete_tls_key_and_crt
        rm -rf ${ssl_chainpath}/*
        timeout "Clear screen!"
        clear
        menu
        ;;
    33)
        timeout "Clear screen!"
        clear
        exit 0
        ;;
    34)
        set_language
        bash idleleo
        ;;
    *)
        clear
        log_echo "${Error} ${RedBG} Please enter the correct number! ${Font}"
        menu
        ;;
    esac
}

check_file_integrity
check_online_version_connect
read_version
judge_mode
idleleo_commend
check_program
check_xray_local_connect
fix_bugs
list "$@"
