#!/bin/bash

# Function to check if the script is run as root
check_root() {
  if [ "$EUID" -ne 0 ]; then
    whiptail --title "Error" --msgbox "Please run this script as root. Use 'sudo $0' to execute it with root privileges." 10 50
    exit 1
  fi
}

# Function to configure GRUB password
configure_grub_password() {
  if whiptail --title "GRUB Password" --yesno "Do you want to configure the GRUB password?" 10 50; then
    if ! grep -q "GRUB_ENABLE_CRYPTODISK" /etc/default/grub; then
      grub_password=$(whiptail --title "GRUB Password" --passwordbox "Enter Grub password:" 10 50 3>&1 1>&2 2>&3)
      if [ $? -eq 0 ]; then
        grub_hash=$(echo -e "$grub_password\n$grub_password" | grub-mkpasswd-pbkdf2 | grep "grub.pbkdf2.sha512")
        echo "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX GRUB_ENABLE_CRYPTODISK=y\"" >> /etc/default/grub
        echo "GRUB_SECRET=\"$grub_hash\"" >> /etc/default/grub
        update-grub
        whiptail --title "Success" --msgbox "Grub password configured successfully. Reboot your system to apply changes." 10 50
      else
        whiptail --title "Error" --msgbox "Grub password configuration canceled. No changes made." 10 50
      fi
    else
      whiptail --title "Info" --msgbox "Grub password configuration already exists. No changes made." 10 50
    fi
  fi
}

# Function to configure IOMMU and memory settings in GRUB
configure_grub_memory() {
  if whiptail --title "GRUB Memory Settings" --yesno "Do you want to configure IOMMU and memory settings in GRUB?" 10 50; then
    timestamp=$(date +"%Y%m%d%H%M%S")
    backup_file="/etc/default/grub.bak_$timestamp"

    sudo cp /etc/default/grub "$backup_file"
    sudo sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 iommu=force l1tf=full,force page_poison=on pti=on slab_nomerge=yes slub_debug=FZP spec_store_bypass_disable=seccomp spectre_v2=off"/' /etc/default/grub
    sudo update-grub
    whiptail --title "Success" --msgbox "IOMMU and memory settings configured. Reboot your system for the changes to take effect." 10 50
  fi
}

# Function to configure kernel and module settings
configure_kernel_and_modules() {
  if whiptail --title "Kernel and Module Settings" --yesno "Do you want to configure kernel and module settings?" 10 50; then
    timestamp=$(date +"%Y%m%d%H%M%S")
    sysctl_conf_backup="/etc/sysctl.conf.bak_$timestamp"
    modules_backup="/etc/modules.bak_$timestamp"

    sudo cp /etc/sysctl.conf "$sysctl_conf_backup"
    echo "
    # Recommended kernel configuration options
    kernel.dmesg_restrict=1
    kernel.kptr_restrict=2
    kernel.pid_max=65536
    kernel.perf_cpu_time_max_percent=1
    kernel.perf_event_max_sample_rate=1
    kernel.perf_event_paranoid=2
    kernel.randomize_va_space=2
    kernel.sysrq=0
    kernel.unprivileged_bpf_disabled=1
    kernel.panic_on_oops=1
    " | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p
    echo "kernel.modules_disabled=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo cp /etc/modules "$modules_backup"

    modules_list=$(lsmod | awk '{print $1}' | tail -n +2)
    selected_modules=$(whiptail --title "Kernel Modules" --checklist "Select modules to add:" 20 60 10 "${modules_list[@]}" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
      echo "# Modules selected by the user" | sudo tee -a /etc/modules > /dev/null
      echo "$selected_modules" | tr ' ' '\n' | sudo tee -a /etc/modules > /dev/null
      whiptail --title "Success" --msgbox "Kernel configuration and module loading restrictions applied. Reboot your system for the changes to take effect." 10 50
    else
      whiptail --title "Error" --msgbox "Kernel configuration and module loading canceled. No changes made." 10 50
    fi
  fi
}

# Function to configure Yama LSM module
configure_yama_lsm() {
  if whiptail --title "Yama LSM Configuration" --yesno "Do you want to configure the Yama LSM module?" 10 50; then
    echo "# Recommended Yama LSM configuration options" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "kernel.yama.ptrace_scope=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p
    whiptail --title "Success" --msgbox "Yama LSM configuration applied. Reboot your system for the changes to take effect." 10 50
  fi
}

# Function to configure IPv4 network settings
configure_ipv4_network() {
  if whiptail --title "IPv4 Network Configuration" --yesno "Do you want to configure IPv4 network settings?" 10 50; then
    echo "# Recommended IPv4 network configuration options" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.core.bpf_jit_harden=2" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.accept_local=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.default.accept_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.secure_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.default.secure_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.shared_media=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.default.shared_media=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.accept_source_route=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.default.accept_source_route=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.arp_filter=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.arp_ignore=2" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.route_localnet=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.drop_gratuitous_arp=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.default.rp_filter=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.rp_filter=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.default.send_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.send_redirects=0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.icmp_ignore_bogus_error_responses=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.ip_local_port_range=32768 65535" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.tcp_rfc1337=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p
    whiptail --title "Success" --msgbox "IPv4 network configuration applied. Reboot your system for the changes to take effect." 10 50
  fi
}

# Function to disable IPv6
disable_ipv6() {
  if whiptail --title "IPv6 Configuration" --yesno "Do you want to disable IPv6?" 10 50; then
    echo "# Disable IPv6 configuration options" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv6.conf.default.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p
    whiptail --title "Success" --msgbox "IPv6 disabled. Reboot your system for the changes to take effect." 10 50
  fi
}

# Function to configure file system settings
configure_file_system() {
  if whiptail --title "File System Configuration" --yesno "Do you want to configure file system settings?" 10 50; then
    echo "# Recommended file system configuration options" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "fs.protected_fifos=2" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "fs.protected_regular=2" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "fs.protected_symlinks=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "fs.protected_hardlinks=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p
    whiptail --title "Success" --msgbox "File system configuration applied. Reboot your system for the changes to take effect." 10 50
  fi
}

# Function to configure kernel compilation options for data structures
configure_kernel_data_structures() {
  if whiptail --title "Kernel Compilation Options - Data Structures" --yesno "Do you want to configure kernel compilation options for data structures?" 10 50; then
    echo "# Recommended kernel compilation options for data structures" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_DEBUG_CREDENTIALS=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_DEBUG_NOTIFIERS=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_DEBUG_LIST=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_DEBUG_SG=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_BUG_ON_DATA_CORRUPTION=y" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for data structures configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel compilation options for memory allocator
configure_kernel_memory_allocator() {
  if whiptail --title "Kernel Compilation Options - Memory Allocator" --yesno "Do you want to configure kernel compilation options for the memory allocator?" 10 50; then
    echo "# Recommended kernel compilation options for the memory allocator" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SLAB_FREELIST_RANDOM=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SLUB=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SLAB_FREELIST_HARDENED=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SLAB_MERGE_DEFAULT=n" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SLUB_DEBUG=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_PAGE_POISONING=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_PAGE_POISONING_NO_SANITY=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_PAGE_POISONING_ZERO=y" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for the memory allocator configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel module management options
configure_kernel_module_management() {
  if whiptail --title "Kernel Module Management Options" --yesno "Do you want to configure kernel module management options?" 10 50; then
    echo "# Recommended kernel module management options" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_MODULES=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_STRICT_MODULE_RWX=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_MODULE_SIG=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_MODULE_SIG_FORCE=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_MODULE_SIG_ALL=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_MODULE_SIG_SHA512=y" | sudo tee -a /etc/default/grub > /dev/null
    echo 'CONFIG_MODULE_SIG_HASH="sha512"' | sudo tee -a /etc/default/grub > /dev/null
    echo 'CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"' | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel module management options configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel panic behavior
configure_kernel_panic() {
  if whiptail --title "Kernel Panic Behavior" --yesno "Do you want to configure kernel panic behavior?" 10 50; then
    echo "# Recommended kernel panic behavior options" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_PANIC_ON_OOPS=y" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel panic behavior configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel compilation options for abnormal events
configure_kernel_abnormal_events() {
  if whiptail --title "Kernel Compilation Options - Abnormal Events" --yesno "Do you want to configure kernel compilation options for abnormal events?" 10 50; then
    echo "# Recommended kernel compilation options for abnormal events" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_BUG=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_PANIC_ON_OOPS=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_PANIC_TIMEOUT=-1" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for abnormal events configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel compilation options for security primitives
configure_kernel_security_primitives() {
  if whiptail --title "Kernel Compilation Options - Security Primitives" --yesno "Do you want to configure kernel compilation options for security primitives?" 10 50; then
    echo "# Recommended kernel compilation options for security primitives" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SECCOMP=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SECCOMP_FILTER=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SECURITY=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SECURITY_YAMA=y" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for security primitives configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel compilation options for compiler plugins
configure_kernel_compiler_plugins() {
  if whiptail --title "Kernel Compilation Options - Compiler Plugins" --yesno "Do you want to configure kernel compilation options for compiler plugins?" 10 50; then
    echo "# Recommended kernel compilation options for compiler plugins" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_GCC_PLUGINS=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_GCC_PLUGIN_STACKLEAK=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_GCC_PLUGIN_STRUCTLEAK=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_GCC_PLUGIN_RANDSTRUCT=y" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for compiler plugins configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel compilation options for network stack
configure_kernel_network_stack() {
  if whiptail --title "Kernel Compilation Options - Network Stack" --yesno "Do you want to configure kernel compilation options for the network stack?" 10 50; then
    echo "# Recommended kernel compilation options for the network stack" | sudo tee -a /etc/default/grub > /dev/null
    echo "# Disable IPv6" | sudo tee -a /etc/default/grub > /dev/null
    echo "#CONFIG_IPV6 is not set" | sudo tee -a /etc/default/grub > /dev/null
    echo "CONFIG_SYN_COOKIES=y" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for the network stack configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# Function to configure kernel compilation options for various kernel behaviors
configure_kernel_behaviors() {
  if whiptail --title "Kernel Compilation Options - Various Behaviors" --yesno "Do you want to configure kernel compilation options for various behaviors?" 10 50; then
    echo "# Recommended kernel compilation options for various behaviors" | sudo tee -a /etc/default/grub > /dev/null
    echo "# Disable unwanted behaviors" | sudo tee -a /etc/default/grub > /dev/null
    echo "#CONFIG_KEXEC is not set" | sudo tee -a /etc/default/grub > /dev/null
    echo "#CONFIG_HIBERNATION is not set" | sudo tee -a /etc/default/grub > /dev/null
    echo "#CONFIG_BINFMT_MISC is not set" | sudo tee -a /etc/default/grub > /dev/null
    echo "#CONFIG_LEGACY_PTYS is not set" | sudo tee -a /etc/default/grub > /dev/null
    echo "#CONFIG_MODULES is not set" | sudo tee -a /etc/default/grub > /dev/null
    whiptail --title "Success" --msgbox "Kernel compilation options for various behaviors configured. Rebuild your kernel to apply changes." 10 50
  fi
}

# LOCK SERVICE ACCOUNTS

SERVICE_ACCOUNTS=("nobody" "www-data" "apache" "nginx" "mysql" "postgres" "redis" "mongodb" "tomcat" "ftp" "mail" "postfix" "exim" "dovecot" "squid" "nfsnobody" "rpc" "rpcuser" "rpcbind" "sshd" "couchdb" "rabbitmq" "memcached" "haproxy" "bind" "named" "sshd" "elasticsearch" "kibana" "logstash" "graylog" "amavis" "clamav" "git" "jenkins" "sonarqube" "cassandra" "neo4j" "samba" "snmp" "tftp" "winbind" "zabbix" "nagios" "gitlab-runner" "jenkins" "gitolite" "gitlab" "gitbucket" "redmine" "sonatype-nexus" "jenkins" "artifactory" "teamcity" "mattermost" "rocket.chat" "gitea" "openvpn" "strongswan" "wireguard" "openldap" "radius" "asterisk" "teamspeak" "mumble" "prosody" "ejabberd" "nfs" "rpcuser" "cyrus" "db2inst1" "db2fenc1" "informix" "ldap" "elasticsearch" "kibana" "logstash" "graylog" "amavis" "clamav" "git" "jenkins" "sonarqube" "cassandra" "neo4j" "samba" "snmp" "tftp" "winbind" "zabbix" "nagios" "gitlab-runner" "jenkins" "gitolite" "gitlab" "gitbucket" "redmine" "sonatype-nexus" "jenkins" "artifactory" "teamcity" "mattermost" "rocket.chat" "gitea" "openvpn" "strongswan" "wireguard" "openldap" "radius" "asterisk" "teamspeak" "mumble" "prosody" "ejabberd" "nfs" "rpcuser" "cyrus" "db2inst1" "db2fenc1" "informix" "ldap")

function lock_service_accounts() {
    whiptail --msgbox "Locking service accounts..." 10 50
    for account in "${SERVICE_ACCOUNTS[@]}"; do
        if grep -qE "^\s*$account\s*:\s*[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:[^:]*$" /etc/passwd; then
            if ! grep -qE "^\s*$account\s*:\s*[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:[^:]*$" /etc/passwd | grep -qE ":\*" /etc/shadow; then
                usermod -L "$account"
                echo "account: $account"
            fi
        fi
    done
    whiptail --title "Success" --msgbox "Service accounts have been locked." 10 50
}

#UMASK value
function umask_value() {
    whiptail --msgbox "Defining UMASK value..." 10 50
    umask -t 027
    whiptail --title "Success" --msgbox "Umask value has been defined" 10 50
}

#Group hardening
function harden_group() {
    if [ -e "/usr/bin/sudo" ]; then
        sudo_group=$(stat -c %G /usr/bin/sudo 2>/dev/null)
        if [ $? -eq 0 ]; then
            if [ "$(stat -c %a /usr/bin/sudo)" = "4110" ]; then
                exit 0
            else
                chmod 4110 /usr/bin/sudo
            fi
        fi
    fi
    exit 1
}

#Service account deactivation
SERVICE_ACCOUNTS=("nobody" "www-data" "apache" "nginx" "mysql" "postgres" "redis" "mongodb" "tomcat" "ftp" "mail" "postfix" "exim" "dovecot" "squid" "nfsnobody" "rpc" "rpcuser" "rpcbind" "sshd" "couchdb" "rabbitmq" "memcached" "haproxy" "bind" "named" "sshd" "elasticsearch" "kibana" "logstash" "graylog" "amavis" "clamav" "git" "jenkins" "sonarqube" "cassandra" "neo4j" "samba" "snmp" "tftp" "winbind" "zabbix" "nagios" "gitlab-runner" "jenkins" "gitolite" "gitlab" "gitbucket" "redmine" "sonatype-nexus" "jenkins" "artifactory" "teamcity" "mattermost" "rocket.chat" "gitea" "openvpn" "strongswan" "wireguard" "openldap" "radius" "asterisk" "teamspeak" "mumble" "prosody" "ejabberd" "nfs" "rpcuser" "cyrus" "db2inst1" "db2fenc1" "informix" "ldap" "elasticsearch" "kibana" "logstash" "graylog" "amavis" "clamav" "git" "jenkins" "sonarqube" "cassandra" "neo4j" "samba" "snmp" "tftp" "winbind" "zabbix" "nagios" "gitlab-runner" "jenkins" "gitolite" "gitlab" "gitbucket" "redmine" "sonatype-nexus" "jenkins" "artifactory" "teamcity" "mattermost" "rocket.chat" "gitea" "openvpn" "strongswan" "wireguard" "openldap" "radius" "asterisk" "teamspeak" "mumble" "prosody" "ejabberd" "nfs" "rpcuser" "cyrus" "db2inst1" "db2fenc1" "informix" "ldap")

function serv_harden() {
    for account in "${SERVICE_ACCOUNTS[@]}"; do
        if [ -n "$(grep -E "^\s*$account\s*:\s*[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:[^:]*$" /etc/passwd)" ]; then
            if [ -z "$(grep -E "^\s*$account\s*:\s*[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:[^:]*$" /etc/passwd | grep -E ":\*" /etc/shadow)" ]; then
                usermod -L $account
            fi
        fi
    done
}

# Main script execution
check_root
configure_grub_password
configure_grub_memory
configure_kernel_and_modules
configure_yama_lsm
configure_ipv4_network
disable_ipv6
configure_file_system
configure_kernel_data_structures
configure_kernel_memory_allocator
configure_kernel_module_management
configure_kernel_panic
configure_kernel_abnormal_events
configure_kernel_security_primitives
configure_kernel_compiler_plugins
configure_kernel_network_stack
configure_kernel_behaviors
lock_service_accounts
umask_value
harden_group
serv_harden