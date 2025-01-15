#!/bin/bash

# 定义当前版本号
mf_SCRIPT_VERSION="1.0.8"

mf_main_menu() {
    check_system
  
    echo -e "\n"
    log_echo "${GreenBG} Configure Fail2ban to prevent brute force attacks, please select: ${Font}"
    log_echo "1. ${Green}Install Fail2ban${Font}"
    log_echo "2. ${Green}Manage Fail2ban${Font}"
    log_echo "3. ${Green}Uninstall Fail2ban${Font}"
    log_echo "4. ${Green}View Fail2ban Status${Font}"
    log_echo "5. ${Green}Exit${Font}"
    read -rp "Please enter: " fail2ban_fq
    [[ -z "${fail2ban_fq}" ]] && fail2ban_fq=1

    case $fail2ban_fq in
        1) mf_install_fail2ban ;;
        2) mf_manage_fail2ban ;;
        3) mf_uninstall_fail2ban ;;
        4) mf_display_fail2ban_status ;;
        5) source "${idleleo}" ;;
        *) 
            echo -e "\n"
            log_echo "${Error} ${RedBG} Invalid selection, please try again ${Font}"
            ;;
    esac
}

mf_install_fail2ban() {
    if command -v fail2ban-client &> /dev/null; then
        log_echo "${OK} ${Green} Fail2ban is already installed, skipping installation ${Font}"
    else
        pkg_install "fail2ban"
        mf_configure_fail2ban
        judge "Fail2ban Installation"
        source "${idleleo}"
    fi
}

mf_configure_fail2ban() {

    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        cp -fp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    # 检查 Nginx 是否安装
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
            log_echo "${Warning} ${YellowBG} Nginx is not installed, please install Nginx first ${Font}"
            return
        fi
    fi

    if [[ -z $(grep "filter   = sshd" /etc/fail2ban/jail.local) ]]; then
        sed -i "/sshd_log/i \enabled  = true\\nfilter   = sshd\\nmaxretry = 5\\nbantime  = 604800" /etc/fail2ban/jail.local
    fi

    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        sed -i "/nginx_error_log/d" /etc/fail2ban/jail.local
        sed -i "s/http,https$/http,https,8080/g" /etc/fail2ban/jail.local
        sed -i "/^maxretry.*= 2$/c \\maxretry = 5" /etc/fail2ban/jail.local
        sed -i "/nginx-botsearch/i \[nginx-badbots]\\n\\nenabled  = true\\nport     = http,https,8080\\nfilter   = apache-badbots\\nlogpath  = ${nginx_dir}/logs/access.log\\nbantime  = 604800\\nmaxretry = 5\\n" /etc/fail2ban/jail.local
        sed -i "/nginx-botsearch/a \\\nenabled  = true\\nfilter   = nginx-botsearch\\nlogpath  = ${nginx_dir}/logs/access.log\\n           ${nginx_dir}/logs/error.log\\nbantime  = 604800" /etc/fail2ban/jail.local
    fi

    # 启用 nginx-no-host 规则
    if [[ ${reality_add_nginx} == "on" ]] && [[ -z $(grep "filter   = nginx-no-host" /etc/fail2ban/jail.local) ]]; then
        mf_create_nginx_no_host_filter
        sed -i "\$ a\\\n[nginx-no-host]\nenabled  = true\nfilter   = nginx-no-host\nlogpath  = $nginx_dir/logs/error.log\nbantime  = 604800\nmaxretry = 600" /etc/fail2ban/jail.local
    fi
    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban Configuration"
}

mf_create_nginx_no_host_filter() {
    local filter_file="/etc/fail2ban/filter.d/nginx-no-host.conf"
    if [[ ! -f "$filter_file" ]]; then
        cat >"$filter_file" <<EOF
[Definition]
failregex = \[error\].*?no host in upstream.*?, client: <HOST>,
ignoreregex =
EOF
    fi
}

mf_manage_fail2ban() {
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban is not installed, please install it first ${Font}"
        return
    fi

    echo -e "\n"
    log_echo "${Green} Please select Fail2ban operation: ${Font}"
    echo "1. Start Fail2ban"
    echo "2. Restart Fail2ban"
    echo "3. Stop Fail2ban"
    echo "4. Add Custom Rule"
    echo "5. Return"
    read_optimize "Please enter: " mf_action 1
    case $mf_action in
        1)
            mf_start_enable_fail2ban
            ;;
        2)
            mf_restart_fail2ban
            mf_main_menu
            ;;
        3)
            mf_stop_disable_fail2ban
            ;;
        4)
            mf_add_custom_rule
            mf_main_menu
            ;;
        5) mf_main_menu ;;
        *)
            echo -e "\n"
            log_echo "${Error} ${RedBG} Invalid selection, please try again ${Font}"
            mf_manage_fail2ban
            ;;
    esac
}

mf_add_custom_rule() {
    local jail_name
    local filter_name
    local log_path
    local max_retry
    local ban_time

    read_optimize "Please enter new Jail name: " "jail_name" NULL
    read_optimize "Please enter Filter name: " "filter_name" NULL
    read_optimize "Please enter log path: " "log_path" NULL
    read_optimize "Please enter maximum retry count (default 5): " "max_retry" 5 1 99 "Maximum retry count must be between 1 and 99"
    read_optimize "Please enter ban time (seconds, default 604800): " "ban_time" 604800 1 8640000 "Ban time must be between 1 and 8640000 seconds"

    if grep -q "\[$jail_name\]" /etc/fail2ban/jail.local; then
        log_echo "${Warning} ${YellowBG} Jail '$jail_name' already exists ${Font}"
        return
    fi

    echo -e "[$jail_name]\nenabled  = true\nfilter   = $filter_name\nlogpath  = $log_path\nmaxretry = $max_retry\nbantime  = $ban_time\n" >> /etc/fail2ban/jail.local
    log_echo "${OK} ${GreenBG} Custom rule added successfully ${Font}"

    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban restart to apply new rules"
}

mf_start_enable_fail2ban() {
    systemctl daemon-reload
    systemctl start fail2ban
    systemctl enable fail2ban
    judge "Fail2ban Start"
    timeout "Clear screen!"
    clear
}

mf_uninstall_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    ${INS} -y remove fail2ban
    [[ -f "/etc/fail2ban/jail.local" ]] && rm -rf /etc/fail2ban/jail.local
    if [[ -f "/etc/fail2ban/filter.d/nginx-no-host.conf" ]]; then
        rm -rf /etc/fail2ban/filter.d/nginx-no-host.conf
    fi
    judge "Fail2ban Uninstallation"
    timeout "Clear screen!"
    clear
    source "${idleleo}"
}

mf_stop_disable_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    log_echo "${OK} ${GreenBG} Fail2ban stopped successfully ${Font}"
    timeout "Clear screen!"
    clear
}

mf_restart_fail2ban() {
    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban Restart"
    timeout "Clear screen!"
    clear
}

mf_display_fail2ban_status() {
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban is not installed, please install it first ${Font}"
        return
    fi

    log_echo "${GreenBG} Fail2ban Overall Status: ${Font}"
    fail2ban-client status

    echo -e "\n"
    log_echo "${Green} Default Enabled Jail Status: ${Font}"
    echo "----------------------------------------"
    log_echo "${Green} SSH Block Status: ${Font}"
    fail2ban-client status sshd
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        log_echo "${Green} Fail2ban Nginx Block Status: ${Font}"
        fail2ban-client status nginx-badbots
        fail2ban-client status nginx-botsearch
        if [[ ${reality_add_nginx} == "on" ]]; then
            log_echo "${Green} Fail2ban Nginx No Host Block Status: ${Font}"
            fail2ban-client status nginx-no-host
        fi
    fi
    mf_main_menu
}

mf_check_for_updates() {
    local latest_version
    local update_choice

    # 直接使用 curl 下载远程版本信息
    latest_version=$(curl -s "$mf_remote_url" | grep 'mf_SCRIPT_VERSION=' | head -n 1 | sed 's/mf_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$mf_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} New version available: $latest_version Current version: $mf_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} Please visit https://github.com/hello-yunshu/Xray_bash_onekey for update notes ${Font}"

        log_echo "${GreenBG} Do you want to download and install the new version [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} Downloading new version... ${Font}"
                curl -sL "$mf_remote_url" -o "${idleleo_dir}/fail2ban_manager.sh"

                if [ $? -eq 0 ]; then
                    chmod +x "${idleleo_dir}/fail2ban_manager.sh"
                    log_echo "${OK} ${Green} Download complete, restarting script... ${Font}"
                    bash "${idleleo}" --set-fail2ban
                else
                    echo -e "\n"
                    log_echo "${Error} ${RedBG} Download failed, please download and install new version manually ${Font}"
                fi
                ;;
            *)
                log_echo "${OK} ${Green} Skipping update ${Font}"
                ;;
        esac
    else
        log_echo "${OK} ${Green} Current version is up to date: $mf_SCRIPT_VERSION ${Font}"
    fi
}

# 检查更新
mf_check_for_updates

mf_main_menu