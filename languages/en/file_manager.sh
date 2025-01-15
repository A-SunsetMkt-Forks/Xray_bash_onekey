#!/bin/bash

# 定义当前版本号
fm_SCRIPT_VERSION="1.0.8"

# 检查是否提供了扩展名参数
if [ -z "$1" ]; then
    echo "Usage: $0 <file extension> [<directory path>]"
    exit 1
fi

fm_EXTENSION="$1"
fm_WORKDIR="${2:-$(pwd)}"

# 检查目录是否存在
if [ ! -d "$fm_WORKDIR" ]; then
    echo -e "\n"
    log_echo "${Error} ${RedBG} Directory $fm_WORKDIR does not exist. Please check the path ${Font}"
    exit 1
fi

# 保存当前工作目录
fm_original_dir=$(pwd)

# 切换到工作目录
cd "$fm_WORKDIR"

# 函数: 列出当前目录下所有指定扩展名的文件
fm_list_files() {
    local max_length
    log_echo "${GreenBG} List all .$fm_EXTENSION files ${Font}"
    
    # 设置 dotglob 选项，使通配符 * 包括以点开头的文件
    shopt -s dotglob
    
    # 使用数组存储匹配到的文件
    files=(*.$fm_EXTENSION)
    
    if [ ${#files[@]} -eq 0 ]; then
        log_echo "${Warning} ${YellowBG} No .$fm_EXTENSION files found ${Font}"
        return 1
    else
        # 计算最大文件名长度
        local max_length=0
        for file in "${files[@]}"; do
            local length=${#file}
            if (( length > max_length )); then
                max_length=$length
            fi
        done
        
        # 确保最小宽度为 10
        if (( max_length < 10 )); then
            max_length=10
        fi
        
        # 计算总宽度（包括边框）
        local total_width=$((max_length + 10))
        
        # 打印表头
        printf "%-${total_width}s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
        
        # 居中文本
        local header_text="Filename"
        local header_length=${#header_text}
        local padding=$(( (total_width - header_length - 4) / 2 ))
        local left_padding=$(( padding - 4 ))  # 加上序号列的宽度
        local right_padding=$(( padding - 4 )) 
        
        printf "| %-4s | %-${left_padding}s%-${header_length}s%-${right_padding}s |\n" "No." "" "$header_text" ""
        
        printf "%-${total_width}s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
        
        # 打印文件名
        local index=1
        for file in "${files[@]}"; do
            printf "| %4d | %-*s |\n" $index $((max_length)) "$file"
            ((index++))
        done
        
        # 打印底部边框
        printf "%-${total_width}s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
        
        return 0
    fi
}

# 函数: 创建一个新的 serverNames 文件
fm_create_servername_file() {
    local url
    fm_list_files
    echo -e "\n"
    log_echo "${Green} Please enter URL (e.g. hey.run)"
    log_echo "${Green} Do not include http:// or https:// prefix ${Font}"
    read_optimize "Please enter: " url
    if [[ $url =~ ^(http|https):// ]]; then
        echo -e "\n"
        log_echo "${Error} ${RedBG} URL cannot include http:// or https:// prefix ${Font}"
        return
    fi
    echo "${url} reality;" > "${url}.serverNames"
    log_echo "${OK} ${GreenBG} File ${url}.serverNames has been created ${Font}"
    fm_restart_nginx_and_check_status
    fm_list_files
}

# 函数: 创建一个新的 wsServers 或 grpcServers 文件
fm_create_ws_or_grpc_server_file() {
    local host port weight content firewall_set_fq
    fm_list_files
    read_optimize "Please enter host: " host
    read_optimize "Please enter port: " port "" 1 65535
    read_optimize "Please enter weight (0~100 default 50): " weight "50" 0 100
    
    content="server ${host}:${port} weight=${weight} max_fails=2 fail_timeout=10;"
    echo "$content" > "${host}.${fm_EXTENSION}"
    log_echo "${OK} ${GreenBG} File ${host}.${fm_EXTENSION} has been created ${Font}"

    # 询问是否需要修改防火墙
    echo -e "\n"
    log_echo "${GreenBG} Do you need to configure firewall [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r firewall_set_fq
    case $firewall_set_fq in
    [yY][eE][sS] | [yY])
                
        if [[ "${ID}" == "centos" ]]; then
            pkg_install "iptables-services"
        else
            pkg_install "iptables-persistent"
        fi
        iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
        iptables -I INPUT -p udp --dport ${port} -j ACCEPT
        iptables -I OUTPUT -p tcp --sport ${port} -j ACCEPT
        iptables -I OUTPUT -p udp --sport ${port} -j ACCEPT
        log_echo "${OK} ${GreenBG} Firewall rules added successfully ${Font}"
        if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
            service iptables save
            service iptables restart
            log_echo "${OK} ${GreenBG} Firewall restarted successfully ${Font}"
        else
            netfilter-persistent save
            systemctl restart iptables
            log_echo "${OK} ${GreenBG} Firewall restarted successfully ${Font}"
        fi
    ;;
    *)
        log_echo "${OK} ${GreenBG} Skipping firewall configuration ${Font}"
        ;;
    esac
    fm_restart_nginx_and_check_status
    fm_list_files
}

# 函数: 编辑一个已存在的指定扩展名的文件
fm_edit_file() {    
    fm_list_files
    local num_files=${#files[@]}
    local choice
    read_optimize "Please enter file number to edit (1-$num_files): " choice "" 1 "$num_files"
    
    local filename="${files[$((choice - 1))]}"
    
    # 检查 vim 是否安装
    if ! command -v vim &> /dev/null; then
        log_echo "${Warning} ${YellowBG} vim not installed. Attempting to install ${Font}"
        pkg_install vim
    fi
    vim "$filename"
    log_echo "${OK} ${GreenBG} File $filename has been edited ${Font}"
    fm_restart_nginx_and_check_status
}

# 函数: 删除一个已存在的指定扩展名的文件
fm_delete_file() {
    if ! fm_list_files; then
        return
    fi
    
    local num_files=${#files[@]}
    local choice
    read_optimize "Please enter file number to delete (1-$num_files): " choice "" 1 "$num_files"
    
    local filename="${files[$((choice - 1))]}"
    
    rm "$filename"
    log_echo "${OK} ${GreenBG} File $filename has been deleted ${Font}"
    fm_restart_nginx_and_check_status
    fm_list_files
}

# 根据扩展名选择创建文件的方式
fm_create_file() {
    case $fm_EXTENSION in
        serverNames)
            fm_create_servername_file
            ;;
        wsServers|grpcServers)
            fm_create_ws_or_grpc_server_file
            ;;
        *)
            echo -e "\n"
            log_echo "${Error} ${RedBG} Unsupported file extension $fm_EXTENSION ${Font}"
            ;;
    esac
}

# 主菜单循环
fm_main_menu() {
    fm_list_files
    while true; do
        echo
        log_echo "${GreenBG} Main Menu ${Font}"
        log_echo "1 ${Green}List all $fm_EXTENSION files${Font}"
        log_echo "2 ${Green}Create a new $fm_EXTENSION file${Font}"
        log_echo "3 ${Green}Edit an existing $fm_EXTENSION file${Font}"
        log_echo "4 ${Green}Delete an existing $fm_EXTENSION file${Font}"
        log_echo "5 ${Green}Exit${Font}"
        local choice
        read_optimize "Please select an option: " choice "" 1 5

        case $choice in
            1) fm_list_files ;;
            2) fm_create_file ;;
            3) fm_edit_file ;;
            4) fm_delete_file ;;
            5) source "$idleleo" ;;
            *) 
                echo -e "\n"
                log_echo "${Error} ${RedBG} Invalid option. Please try again ${Font}"
                ;;
        esac
    done
}

fm_check_for_updates() {
    local latest_version
    local update_choice

    # 直接使用 curl 下载远程版本信息
    latest_version=$(curl -s "$fm_remote_url" | grep 'fm_SCRIPT_VERSION=' | head -n 1 | sed 's/fm_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$fm_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} New version available: $latest_version Current version: $fm_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} Please visit https://github.com/hello-yunshu/Xray_bash_onekey for update notes ${Font}"

        log_echo "${GreenBG} Do you want to download and install the new version [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} Downloading new version... ${Font}"
                curl -sL "$fm_remote_url" -o "${idleleo_dir}/file_manager.sh"

                if [ $? -eq 0 ]; then
                    chmod +x "${idleleo_dir}/file_manager.sh"
                    log_echo "${OK} ${Green} Download complete, restarting script... ${Font}"
                    bash "${idleleo}" --add-servernames
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
        log_echo "${OK} ${Green} Current version is up to date: $fm_SCRIPT_VERSION ${Font}"
    fi
}

fm_restart_nginx_and_check_status() {
    if [[ -f ${nginx_systemd_file} ]]; then
        systemctl restart nginx
        if systemctl is-active --quiet nginx; then
            echo -e "\n"
            log_echo "${OK} ${GreenBG} Nginx restarted successfully ${Font}"
        else
            echo -e "\n"
            log_echo "${Error} ${RedBG} Nginx restart failed. Please check configuration file for errors ${Font}"
            fm_edit_file
        fi
    fi
}

# 检查更新
fm_check_for_updates

# 运行主菜单
fm_main_menu

# 恢复原始工作目录
cd "$fm_original_dir" || exit 1