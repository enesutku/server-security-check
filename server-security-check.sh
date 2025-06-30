#!/bin/bash

# Server Security Check
# Version: 1.0
# Author: Enes UTKU

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Special characters
CHECK_MARK="✓"
CROSS_MARK="✗"
WARNING_MARK="⚠"

# Global variables
REPORT_FILE="/tmp/ubuntu_security_report.txt"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0
TEST_RESULTS=""
SERVER_TYPE=""

# Simple loading animation with dots
show_loading() {
    local message="$1"
    local duration="$2"
    printf "\033[0;36m%s\033[0m" "$message"
    
    for i in $(seq 1 $duration); do
        printf "\033[0;36m.\033[0m"
        sleep 0.2
    done
    printf " \033[0;32mDone!\033[0m\n"
}

# Server type selection
select_server_type() {
    clear
    printf "\033[0;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n"
    printf "\033[0;35m║\033[1;37m                      SERVER SECURITY ANALYSIS                    \033[0;35m║\033[0m\n"
    printf "\033[0;35m║\033[1;33m                        Server Type Selection                     \033[0;35m║\033[0m\n"
    printf "\033[0;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n"
    echo ""
    printf "\033[1;36mPlease select your server type for specialized security testing:\033[0m\n"
    echo ""
    printf "\033[1;32m1)\033[0m \033[1;37mGeneral Server\033[0m  \033[0;33m(Standard server, no specific role)\033[0m\n"
    printf "\033[1;32m2)\033[0m \033[1;37mWeb Server\033[0m      \033[0;33m(Apache, Nginx, HTTP/HTTPS services)\033[0m\n"
    printf "\033[1;32m3)\033[0m \033[1;37mDatabase Server\033[0m \033[0;33m(MySQL, PostgreSQL, MariaDB)\033[0m\n"
    printf "\033[1;32m4)\033[0m \033[1;37mMail Server\033[0m     \033[0;33m(Postfix, Dovecot, SMTP/IMAP)\033[0m\n"
    printf "\033[1;32m5)\033[0m \033[1;37mDNS Server\033[0m      \033[0;33m(BIND, Unbound, DNS services)\033[0m\n"
    printf "\033[1;32m6)\033[0m \033[1;37mFile Server\033[0m     \033[0;33m(Samba, NFS, file sharing)\033[0m\n"
    echo ""
    
    while true; do
        printf "\033[1;36mEnter your choice (1-6): \033[0m"
        read choice
        case $choice in
            1) SERVER_TYPE="general"; break;;
            2) SERVER_TYPE="web"; break;;
            3) SERVER_TYPE="database"; break;;
            4) SERVER_TYPE="mail"; break;;
            5) SERVER_TYPE="dns"; break;;
            6) SERVER_TYPE="file"; break;;
            *) printf "\033[0;31mInvalid choice. Please enter 1-6.\033[0m\n";;
        esac
    done
    
    echo ""
    printf "\033[1;32m✓ Selected server type: \033[1;37m$SERVER_TYPE\033[0m\n"
    printf "\033[0;36mSpecialized tests will be performed for this server type.\033[0m\n"
    sleep 2
}

# Print banner
print_banner() {
    clear
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                       SERVER SECURITY ANALYSIS                   ║"
    echo "║                        Comprehensive Analysis                    ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Starting security assessment at: $(date)"
    echo "Report will be saved to: $REPORT_FILE"
    echo "Server type: $SERVER_TYPE"
    echo ""
}

# Add test result
add_test_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$status" = "PASS" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        TEST_RESULTS="$TEST_RESULTS
$CHECK_MARK $test_name"
    elif [ "$status" = "FAIL" ]; then
        FAILED_TESTS=$((FAILED_TESTS + 1))
        TEST_RESULTS="$TEST_RESULTS
$CROSS_MARK $test_name - $details"
    elif [ "$status" = "INFO" ]; then
        # INFO level doesn't count as warning/pass/fail
        TEST_RESULTS="$TEST_RESULTS
ⓘ  $test_name - $details"
    else
        WARNING_TESTS=$((WARNING_TESTS + 1))
        TEST_RESULTS="$TEST_RESULTS
$WARNING_MARK $test_name - $details"
    fi
    
    echo "[$status] $test_name - $details" >> "$REPORT_FILE"
}

# Initialize report
init_report() {
    cat > "$REPORT_FILE" << EOF
Ubuntu Security Assessment Report
Generated on: $(date)
System: $(uname -a)
User: $(whoami)
Server Type: $SERVER_TYPE

================================================================================
SECURITY TEST RESULTS
================================================================================

EOF
}

# System Information Tests
test_system_info() {
    show_loading "Gathering system information" 8
    
    # OS Version Check
    ubuntu_version=$(lsb_release -r 2>/dev/null | awk '{print $2}')
    if [ ! -z "$ubuntu_version" ]; then
        add_test_result "Ubuntu Version Detection" "PASS" "Version: $ubuntu_version"
    else
        add_test_result "Ubuntu Version Detection" "FAIL" "Could not determine Ubuntu version"
    fi
    
    # Kernel Version
    kernel_version=$(uname -r)
    add_test_result "Kernel Version Check" "PASS" "Kernel: $kernel_version"
    
    # System Uptime
    uptime_info=$(uptime | awk '{print $3, $4}' | sed 's/,//')
    add_test_result "System Uptime" "PASS" "Uptime: $uptime_info"
    
    # Architecture
    arch=$(uname -m)
    add_test_result "System Architecture" "PASS" "Architecture: $arch"
}

# User and Authentication Tests
test_user_authentication() {
    show_loading "Analyzing user accounts and authentication" 10
    
    # Root account UID check
    root_uid_count=$(awk -F: '($3 == "0") {print}' /etc/passwd | wc -l)
    if [ "$root_uid_count" -eq 1 ]; then
        add_test_result "Root UID Uniqueness" "PASS" "Only root has UID 0"
    else
        add_test_result "Root UID Uniqueness" "FAIL" "Multiple accounts with UID 0 found"
    fi
    
    # Empty password check
    empty_passwd=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [ "$empty_passwd" -eq 0 ]; then
        add_test_result "Empty Password Check" "PASS" "No accounts with empty passwords"
    else
        add_test_result "Empty Password Check" "FAIL" "$empty_passwd accounts with empty passwords found"
    fi
    
    # Password aging check
    if grep -q "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null; then
        max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ "$max_days" -le 90 ]; then
            add_test_result "Password Aging Policy" "PASS" "Max password age: $max_days days"
        else
            add_test_result "Password Aging Policy" "WARN" "Password max age is $max_days days (recommended: ≤90)"
        fi
    else
        add_test_result "Password Aging Policy" "FAIL" "Password aging not configured"
    fi
    
    # Check for users with shell access
    shell_users=$(grep -E "/(bash|sh|zsh|fish)$" /etc/passwd | wc -l)
    add_test_result "Shell Access Users" "PASS" "$shell_users users with shell access"
}

# SSH Security Tests
test_ssh_security() {
    show_loading "Checking SSH security settings" 12
    
    # Check if SSH is running
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
        add_test_result "SSH Service Status" "PASS" "SSH service is active"
        
        # SSH configuration checks
        ssh_config="/etc/ssh/sshd_config"
        
        # Root login check
        if [ -f "$ssh_config" ]; then
            if grep -q "^PermitRootLogin.*no" "$ssh_config" 2>/dev/null; then
                add_test_result "SSH Root Login Disabled" "PASS" "Root login disabled"
            elif grep -q "^PermitRootLogin" "$ssh_config" 2>/dev/null; then
                add_test_result "SSH Root Login Disabled" "FAIL" "Root login may be enabled"
            else
                add_test_result "SSH Root Login Configuration" "INFO" "Root login setting not explicitly configured (using defaults)"
            fi
            
            # Password authentication check
            if grep -q "^PasswordAuthentication.*no" "$ssh_config" 2>/dev/null; then
                add_test_result "SSH Password Authentication" "PASS" "Password authentication disabled"
            elif grep -q "^PasswordAuthentication" "$ssh_config" 2>/dev/null; then
                add_test_result "SSH Password Authentication" "WARN" "Password authentication may be enabled"
            else
                add_test_result "SSH Password Authentication" "INFO" "Password authentication setting not explicit (using defaults)"
            fi
            
            # Check SSH port
            ssh_port=$(grep "^Port" "$ssh_config" 2>/dev/null | awk '{print $2}')
            if [ ! -z "$ssh_port" ] && [ "$ssh_port" != "22" ]; then
                add_test_result "SSH Port Configuration" "PASS" "SSH running on non-default port: $ssh_port"
            else
                add_test_result "SSH Port Configuration" "WARN" "SSH running on default port 22"
            fi
        else
            add_test_result "SSH Config File" "WARN" "SSH config file not found"
        fi
        
    else
        add_test_result "SSH Service Status" "PASS" "SSH service not running (good for security)"
    fi
}

# Firewall Tests
test_firewall() {
    show_loading "Analyzing firewall configuration" 10
    
    # UFW status
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')
        if [ "$ufw_status" = "active" ]; then
            add_test_result "UFW Firewall Status" "PASS" "UFW is active"
            
            # Check default policies
            deny_incoming=$(ufw status verbose 2>/dev/null | grep "Default:" | grep "deny (incoming)")
            if [ ! -z "$deny_incoming" ]; then
                add_test_result "UFW Default Incoming Policy" "PASS" "Default deny incoming"
            else
                add_test_result "UFW Default Incoming Policy" "FAIL" "Default incoming policy not set to deny"
            fi
        else
            add_test_result "UFW Firewall Status" "FAIL" "UFW is inactive"
        fi
    else
        add_test_result "UFW Firewall Installation" "WARN" "UFW not installed"
    fi
    
    # iptables rules check
    if command -v iptables >/dev/null 2>&1; then
        iptables_rules=$(iptables -L 2>/dev/null | wc -l)
        if [ "$iptables_rules" -gt 10 ]; then
            add_test_result "Iptables Rules" "PASS" "$iptables_rules iptables rules configured"
        else
            add_test_result "Iptables Rules" "WARN" "Few or no iptables rules found"
        fi
    else
        add_test_result "Iptables Installation" "WARN" "iptables not found"
    fi
}

# Network Security Tests
test_network_security() {
    show_loading "Checking network security settings" 15
    
    # Check listening services
    if command -v netstat >/dev/null 2>&1; then
        listening_services=$(netstat -tlnp 2>/dev/null | grep LISTEN | wc -l)
        add_test_result "Listening Services" "PASS" "$listening_services services listening on network ports"
    else
        add_test_result "Network Tools" "INFO" "netstat not found (using ss command instead)"
    fi
    
    # Check for unnecessary services
    for service in telnet ftp rsh rcp rlogin; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            add_test_result "Insecure Service: $service" "FAIL" "$service is running (insecure)"
        else
            add_test_result "Insecure Service: $service" "PASS" "$service is not running"
        fi
    done
    
    # IP forwarding check
    if [ -f /proc/sys/net/ipv4/ip_forward ]; then
        ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
        if [ "$ip_forward" = "0" ]; then
            add_test_result "IP Forwarding" "PASS" "IP forwarding disabled"
        else
            add_test_result "IP Forwarding" "WARN" "IP forwarding enabled"
        fi
    fi
    
    # ICMP redirect check
    if [ -f /proc/sys/net/ipv4/conf/all/accept_redirects ]; then
        icmp_redirect=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null)
        if [ "$icmp_redirect" = "0" ]; then
            add_test_result "ICMP Redirects" "PASS" "ICMP redirects disabled"
        else
            add_test_result "ICMP Redirects" "WARN" "ICMP redirects enabled"
        fi
    fi
}

# File System Security Tests
test_filesystem_security() {
    show_loading "Analyzing file system permissions and integrity" 18
    
    # Check /tmp permissions
    if [ -d /tmp ]; then
        tmp_perms=$(stat -c "%a" /tmp 2>/dev/null)
        if [ "$tmp_perms" = "1777" ]; then
            add_test_result "/tmp Directory Permissions" "PASS" "Correct permissions (1777)"
        else
            add_test_result "/tmp Directory Permissions" "WARN" "Permissions: $tmp_perms (expected: 1777)"
        fi
    fi
    
    # Check for world-writable files
    world_writable=$(find /etc /bin /sbin /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | wc -l)
    if [ "$world_writable" -eq 0 ]; then
        add_test_result "World-Writable System Files" "PASS" "No world-writable system files found"
    else
        add_test_result "World-Writable System Files" "FAIL" "$world_writable world-writable system files found"
    fi
    
    # Check for SUID/SGID files
    suid_files=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    add_test_result "SUID/SGID Files" "PASS" "$suid_files SUID/SGID files found"
    
    # Check /etc/passwd and /etc/shadow permissions
    if [ -f /etc/passwd ]; then
        passwd_perms=$(stat -c "%a" /etc/passwd 2>/dev/null)
        if [ "$passwd_perms" = "644" ]; then
            add_test_result "/etc/passwd Permissions" "PASS" "Correct permissions (644)"
        else
            add_test_result "/etc/passwd Permissions" "WARN" "Permissions: $passwd_perms (expected: 644)"
        fi
    fi
    
    if [ -f /etc/shadow ]; then
        shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
        if [ "$shadow_perms" = "640" ] || [ "$shadow_perms" = "600" ]; then
            add_test_result "/etc/shadow Permissions" "PASS" "Correct permissions ($shadow_perms)"
        else
            add_test_result "/etc/shadow Permissions" "FAIL" "Permissions: $shadow_perms (expected: 640 or 600)"
        fi
    fi
}

# Package Security Tests
test_package_security() {
    show_loading "Checking package integrity and updates" 15
    
    # Check for available updates
    if command -v apt >/dev/null 2>&1; then
        updates_available=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
        if [ "$updates_available" -eq 0 ]; then
            add_test_result "System Updates" "PASS" "System is up to date"
        else
            add_test_result "System Updates" "WARN" "$updates_available updates available"
        fi
        
        # Security updates are checked separately in test_security_updates function
    else
        add_test_result "Package Manager" "WARN" "apt not found"
    fi
    
    # Check automatic updates
    if [ -f "/etc/apt/apt.conf.d/20auto-upgrades" ]; then
        auto_updates=$(grep "APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | grep -o '"[0-9]*"' | tr -d '"')
        if [ "$auto_updates" = "1" ]; then
            add_test_result "Automatic Updates" "PASS" "Automatic updates enabled"
        else
            add_test_result "Automatic Updates" "WARN" "Automatic updates disabled"
        fi
    else
        add_test_result "Automatic Updates" "WARN" "Automatic updates not configured"
    fi
}

# Security Tools Tests
test_security_tools() {
    show_loading "Scanning for security tools" 10
    
    # Check if fail2ban is installed and running
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        add_test_result "Fail2ban Service" "PASS" "Fail2ban is running"
    else
        add_test_result "Fail2ban Service" "WARN" "Fail2ban not running - protects against brute force attacks"
    fi
}

# Kernel Security Tests
test_kernel_security() {
    show_loading "Analyzing kernel security parameters" 12
    
    # Check ASLR (Address Space Layout Randomization)
    if [ -f /proc/sys/kernel/randomize_va_space ]; then
        aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
        if [ "$aslr" = "2" ]; then
            add_test_result "ASLR (Address Space Layout Randomization)" "PASS" "ASLR fully enabled"
        elif [ "$aslr" = "1" ]; then
            add_test_result "ASLR (Address Space Layout Randomization)" "WARN" "ASLR partially enabled"
        else
            add_test_result "ASLR (Address Space Layout Randomization)" "FAIL" "ASLR disabled"
        fi
    fi
    
    # Check DEP/NX bit support
    if grep -q "nx" /proc/cpuinfo 2>/dev/null; then
        add_test_result "DEP/NX Bit Support" "PASS" "DEP/NX bit supported and enabled"
    else
        add_test_result "DEP/NX Bit Support" "WARN" "DEP/NX bit not detected or unsupported"
    fi
    
    # Check kernel version for known vulnerabilities
    kernel_version=$(uname -r)
    add_test_result "Kernel Version Analysis" "PASS" "Kernel: $kernel_version (manual review recommended)"
    
    # Check if kernel modules can be loaded
    if [ -f /proc/sys/kernel/modules_disabled ]; then
        modules_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)
        if [ "$modules_disabled" = "1" ]; then
            add_test_result "Kernel Module Loading" "PASS" "Kernel module loading disabled"
        else
            add_test_result "Kernel Module Loading" "INFO" "Kernel module loading enabled (normal operation)"
        fi
    else
        add_test_result "Kernel Module Loading" "WARN" "Kernel module loading restriction not configured"
    fi
    
    # Check for kernel pointer restriction
    if [ -f /proc/sys/kernel/kptr_restrict ]; then
        kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
        if [ "$kptr_restrict" = "1" ] || [ "$kptr_restrict" = "2" ]; then
            add_test_result "Kernel Pointer Restriction" "PASS" "Kernel pointers restricted"
        else
            add_test_result "Kernel Pointer Restriction" "WARN" "Kernel pointers not restricted"
        fi
    fi
}

# Mount Security Tests
test_mount_security() {
    show_loading "Checking mount security options" 10
    
    # Check /tmp mount options
    if mount | grep -q "on /tmp "; then
        tmp_mount=$(mount | grep "on /tmp ")
        if echo "$tmp_mount" | grep -q "noexec"; then
            add_test_result "/tmp Mount - noexec" "PASS" "/tmp mounted with noexec"
        else
            add_test_result "/tmp Mount - noexec" "WARN" "/tmp not mounted with noexec option"
        fi
        
        if echo "$tmp_mount" | grep -q "nosuid"; then
            add_test_result "/tmp Mount - nosuid" "PASS" "/tmp mounted with nosuid"
        else
            add_test_result "/tmp Mount - nosuid" "WARN" "/tmp not mounted with nosuid option"
        fi
    else
        add_test_result "/tmp Mount Configuration" "INFO" "/tmp not mounted separately (consider for enhanced security)"
    fi
    
    # Check /var/tmp mount options
    if mount | grep -q "on /var/tmp "; then
        vartmp_mount=$(mount | grep "on /var/tmp ")
        if echo "$vartmp_mount" | grep -q "noexec"; then
            add_test_result "/var/tmp Mount - noexec" "PASS" "/var/tmp mounted with noexec"
        else
            add_test_result "/var/tmp Mount - noexec" "WARN" "/var/tmp not mounted with noexec option"
        fi
    else
        add_test_result "/var/tmp Mount Configuration" "INFO" "/var/tmp not mounted separately (consider for enhanced security)"
    fi
    
    # Check for removable media mount restrictions
    if mount | grep -E "(usb|cdrom|floppy)" | grep -q "noexec"; then
        add_test_result "Removable Media Security" "PASS" "Removable media mounted with security options"
    else
        add_test_result "Removable Media Security" "PASS" "No removable media currently mounted"
    fi
}

# Logging and Audit Tests
test_logging_audit() {
    show_loading "Analyzing logging and audit systems" 12
    
    # Check rsyslog service
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        add_test_result "Rsyslog Service" "PASS" "rsyslog is running"
    else
        add_test_result "Rsyslog Service" "WARN" "rsyslog not running - system logging disabled"
    fi
    
    # Check auditd service
    if systemctl is-active --quiet auditd 2>/dev/null; then
        add_test_result "Audit Daemon" "PASS" "auditd is running"
        
        # Check audit rules
        if command -v auditctl >/dev/null 2>&1; then
            audit_rules=$(auditctl -l 2>/dev/null | wc -l)
            if [ "$audit_rules" -gt 0 ]; then
                add_test_result "Audit Rules" "PASS" "$audit_rules audit rules configured"
            else
                add_test_result "Audit Rules" "WARN" "No audit rules configured"
            fi
        fi
    else
        add_test_result "Audit Daemon" "WARN" "auditd not running - security auditing disabled"
    fi
    
    # Check log file permissions
    log_files="/var/log/auth.log /var/log/syslog /var/log/kern.log"
    for log_file in $log_files; do
        if [ -f "$log_file" ]; then
            log_perms=$(stat -c "%a" "$log_file" 2>/dev/null)
            if [ "$log_perms" = "640" ] || [ "$log_perms" = "644" ] || [ "$log_perms" = "600" ]; then
                add_test_result "Log File Permissions: $(basename $log_file)" "PASS" "Correct permissions ($log_perms)"
            else
                add_test_result "Log File Permissions: $(basename $log_file)" "WARN" "Permissions: $log_perms"
            fi
        else
            add_test_result "Log File Exists: $(basename $log_file)" "WARN" "Log file missing"
        fi
    done
    
    # Check logrotate configuration
    if [ -f /etc/logrotate.conf ]; then
        add_test_result "Log Rotation Configuration" "PASS" "logrotate configured"
    else
        add_test_result "Log Rotation Configuration" "WARN" "logrotate not configured"
    fi
}

# Time Synchronization Tests
test_time_sync() {
    show_loading "Checking time synchronization" 8
    
    # Check NTP/timesyncd service
    if systemctl is-active --quiet ntp 2>/dev/null; then
        add_test_result "NTP Service" "PASS" "NTP daemon is running"
    elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        add_test_result "Time Synchronization" "PASS" "systemd-timesyncd is running"
    elif systemctl is-active --quiet chrony 2>/dev/null; then
        add_test_result "Chrony Service" "PASS" "chrony daemon is running"
    else
        add_test_result "Time Synchronization" "WARN" "No time synchronization service running"
    fi
    
    # Check time accuracy
    if command -v timedatectl >/dev/null 2>&1; then
        time_status=$(timedatectl status 2>/dev/null | grep "synchronized" | awk '{print $3}')
        if [ "$time_status" = "yes" ]; then
            add_test_result "Time Synchronization Status" "PASS" "System clock synchronized"
        else
            add_test_result "Time Synchronization Status" "WARN" "System clock not synchronized"
        fi
    fi
}

# System Service Security Tests
test_system_services() {
    show_loading "Analyzing system services security" 15
    
    # Check for unnecessary services (only if not relevant to server type)
    unnecessary_services="avahi-daemon cups bluetooth"
    for service in $unnecessary_services; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            add_test_result "Service Analysis: $service" "WARN" "$service is running (review if needed)"
        else
            add_test_result "Service Analysis: $service" "PASS" "$service is not running"
        fi
    done
    
    # Check for potentially unnecessary services based on server type
    case "$SERVER_TYPE" in
        "web")
            # Check if database services are running when not needed
            for db_service in mysql mariadb postgresql; do
                if systemctl is-active --quiet "$db_service" 2>/dev/null; then
                    add_test_result "Unexpected Service: $db_service" "WARN" "$db_service running (review if needed for this server type)"
                fi
            done
            ;;
        "database") 
            # Check if web services are running when not needed  
            for web_service in apache2 nginx; do
                if systemctl is-active --quiet "$web_service" 2>/dev/null; then
                    add_test_result "Unexpected Service: $web_service" "WARN" "$web_service running (review if needed for this server type)"
                fi
            done
            ;;
        "general")
            # For general servers, check for specialized services
            specialized_services="mysql mariadb postgresql apache2 nginx postfix dovecot bind9 named smbd nmbd docker"
            for service in $specialized_services; do
                if systemctl is-active --quiet "$service" 2>/dev/null; then
                    add_test_result "Specialized Service: $service" "INFO" "$service running (consider server type classification)"
                fi
            done
            ;;
    esac
}

# Process Security Tests
test_process_security() {
    show_loading "Analyzing running processes" 10
    
    # Check processes running as root
    root_processes=$(ps -eo user | grep -c "^root$")
    add_test_result "Root Processes Count" "PASS" "$root_processes processes running as root"
    
    # Check for suspicious processes
    total_processes=$(ps aux | wc -l)
    add_test_result "Total Process Count" "PASS" "$total_processes total processes running"
    
    # Check for processes listening on unusual ports
    if command -v netstat >/dev/null 2>&1; then
        high_ports=$(netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n | awk '$1 > 1024 && $1 < 65535' | wc -l)
        add_test_result "High Port Listeners" "PASS" "$high_ports services listening on high ports"
    fi
    
    # Check AppArmor status
    if command -v aa-status >/dev/null 2>&1; then
        aa_profiles=$(aa-status --enabled 2>/dev/null | wc -l)
        if [ "$aa_profiles" -gt 0 ]; then
            add_test_result "AppArmor Security" "PASS" "$aa_profiles AppArmor profiles active"
        else
            add_test_result "AppArmor Security" "INFO" "No AppArmor profiles active (consider enabling for enhanced security)"
        fi
    else
        add_test_result "AppArmor Installation" "WARN" "AppArmor not installed"
    fi
}

# SSL Certificate Security Tests
test_ssl_security() {
    show_loading "Checking SSL certificate security" 8
    
    # Check for SSL certificates
    ssl_dirs="/etc/ssl/certs /etc/ssl/private /etc/letsencrypt/live"
    cert_count=0
    
    for ssl_dir in $ssl_dirs; do
        if [ -d "$ssl_dir" ]; then
            certs=$(find "$ssl_dir" -name "*.crt" -o -name "*.pem" -o -name "*.cert" 2>/dev/null | wc -l)
            cert_count=$((cert_count + certs))
        fi
    done
    
    if [ "$cert_count" -gt 0 ]; then
        add_test_result "SSL Certificates Found" "PASS" "$cert_count SSL certificates found"
        
        # Check certificate expiration (basic check)
        expired_certs=0
        expiring_soon=0
        
        for ssl_dir in $ssl_dirs; do
            if [ -d "$ssl_dir" ]; then
                find "$ssl_dir" -name "*.crt" -o -name "*.pem" 2>/dev/null | while read cert_file; do
                    if command -v openssl >/dev/null 2>&1 && [ -f "$cert_file" ]; then
                        if openssl x509 -in "$cert_file" -noout -checkend 2592000 >/dev/null 2>&1; then
                            : # Certificate valid for next 30 days
                        else
                            expiring_soon=$((expiring_soon + 1))
                        fi
                        
                        if openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
                            : # Certificate not expired
                        else
                            expired_certs=$((expired_certs + 1))
                        fi
                    fi
                done
            fi
        done
        
        if [ "$expired_certs" -eq 0 ]; then
            add_test_result "SSL Certificate Expiration" "PASS" "No expired certificates found"
        else
            add_test_result "SSL Certificate Expiration" "FAIL" "$expired_certs expired certificates"
        fi
        
        if [ "$expiring_soon" -eq 0 ]; then
            add_test_result "SSL Certificate Validity" "PASS" "All certificates valid for 30+ days"
        else
            add_test_result "SSL Certificate Validity" "WARN" "$expiring_soon certificates expiring within 30 days"
        fi
    else
        add_test_result "SSL Certificates" "WARN" "No SSL certificates found"
    fi
    
    # Check SSL configuration files
    ssl_configs="/etc/ssl/openssl.cnf"
    for config in $ssl_configs; do
        if [ -f "$config" ]; then
            config_perms=$(stat -c "%a" "$config" 2>/dev/null)
            if [ "$config_perms" = "644" ] || [ "$config_perms" = "640" ]; then
                add_test_result "SSL Config Permissions" "PASS" "SSL config permissions secure"
            else
                add_test_result "SSL Config Permissions" "WARN" "SSL config permissions: $config_perms"
            fi
        fi
    done
}

# Disk Encryption Status Tests
test_disk_encryption() {
    show_loading "Checking disk encryption status" 6
    
    # Check for LUKS encrypted devices
    if command -v cryptsetup >/dev/null 2>&1; then
        luks_devices=$(blkid 2>/dev/null | grep -c "TYPE=\"crypto_LUKS\"" || echo "0")
        luks_devices=$(echo "$luks_devices" | tr -d '\n')
        if [ "$luks_devices" -gt 0 ]; then
            add_test_result "LUKS Encryption" "PASS" "$luks_devices LUKS encrypted devices found"
        else
            add_test_result "LUKS Encryption" "INFO" "No LUKS encrypted devices found (consider for sensitive data)"
        fi
        
        # Check for active encrypted volumes
        active_luks=0
        if command -v lsblk >/dev/null 2>&1; then
            for device in $(lsblk -rno NAME,TYPE | awk '$2=="crypt" {print $1}' 2>/dev/null); do
                if [ ! -z "$device" ]; then
                    active_luks=$((active_luks + 1))
                fi
            done
        fi
        if [ "$active_luks" -gt 0 ]; then
            add_test_result "Active Encrypted Volumes" "PASS" "$active_luks active encrypted volumes"
        else
            add_test_result "Active Encrypted Volumes" "INFO" "No active encrypted volumes (consider for sensitive data)"
        fi
    else
        add_test_result "Cryptsetup Tool" "WARN" "cryptsetup not installed"
    fi
    
    # Check for encrypted swap
    if swapon --show 2>/dev/null | grep -q "/dev/mapper/"; then
        add_test_result "Encrypted Swap" "PASS" "Encrypted swap detected"
    elif grep -q "swap" /proc/swaps 2>/dev/null; then
        add_test_result "Encrypted Swap" "WARN" "Unencrypted swap in use"
    else
        add_test_result "Swap Status" "PASS" "No swap configured"
    fi
    
    # Check home directory encryption
    if [ -d "/home/.ecryptfs" ]; then
        add_test_result "Home Directory Encryption" "PASS" "eCryptfs home encryption available"
    else
        add_test_result "Home Directory Encryption" "WARN" "No home directory encryption detected"
    fi
}

# Disk Space Security Tests
test_disk_space_security() {
    show_loading "Checking disk space security" 5
    
    # Check critical partition usage
    critical_partitions="/ /var /tmp /home"
    for partition in $critical_partitions; do
        if df "$partition" >/dev/null 2>&1; then
            usage=$(df "$partition" | awk 'NR==2 {print $5}' | sed 's/%//')
            if [ "$usage" -lt 80 ]; then
                add_test_result "Disk Usage: $partition" "PASS" "$usage% used"
            elif [ "$usage" -lt 95 ]; then
                add_test_result "Disk Usage: $partition" "WARN" "$usage% used (high usage)"
            else
                add_test_result "Disk Usage: $partition" "FAIL" "$usage% used (critical)"
            fi
        fi
    done
    
    # Check for separate /tmp partition
    if mount | grep -q " /tmp "; then
        add_test_result "Separate /tmp Partition" "PASS" "/tmp is on separate partition"
    else
        add_test_result "Separate /tmp Partition" "INFO" "/tmp not on separate partition (best practice for enterprise)"
    fi
    
    # Check for separate /var partition
    if mount | grep -q " /var "; then
        add_test_result "Separate /var Partition" "PASS" "/var is on separate partition"
    else
        add_test_result "Separate /var Partition" "INFO" "/var not on separate partition (best practice for enterprise)"
    fi
    
    # Check inodes usage
    inode_usage=$(df -i / | awk 'NR==2 {print $5}' | sed 's/%//' 2>/dev/null || echo "0")
    if [ "$inode_usage" -lt 80 ]; then
        add_test_result "Inode Usage" "PASS" "$inode_usage% inodes used"
    else
        add_test_result "Inode Usage" "WARN" "$inode_usage% inodes used (high)"
    fi
}

# Open Ports Analysis Tests
test_open_ports_analysis() {
    show_loading "Analyzing open ports" 8
    
    # Check for common dangerous ports
    dangerous_ports="23 135 139 445 1433 1521 3389 5432 5900"
    open_dangerous=0
    
    for port in $dangerous_ports; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            service_name=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f2)
            add_test_result "Dangerous Port $port" "WARN" "Port $port open ($service_name)"
            open_dangerous=$((open_dangerous + 1))
        fi
    done
    
    if [ "$open_dangerous" -eq 0 ]; then
        add_test_result "Dangerous Ports Check" "PASS" "No commonly dangerous ports open"
    fi
    
    # Count total open ports
    total_open_tcp=$(netstat -tln 2>/dev/null | grep LISTEN | wc -l)
    total_open_udp=$(netstat -uln 2>/dev/null | wc -l)
    
    add_test_result "Open TCP Ports" "PASS" "$total_open_tcp TCP ports listening"
    add_test_result "Open UDP Ports" "PASS" "$total_open_udp UDP ports open"
    
    # Check for IPv6 ports
    ipv6_ports=$(netstat -tln6 2>/dev/null | grep LISTEN | wc -l)
    if [ "$ipv6_ports" -gt 0 ]; then
        add_test_result "IPv6 Listening Ports" "PASS" "$ipv6_ports IPv6 ports listening"
    else
        add_test_result "IPv6 Services" "PASS" "No IPv6 services listening"
    fi
    
    # Check for services listening on all interfaces (0.0.0.0)
    all_interface_services=$(netstat -tln 2>/dev/null | grep "0.0.0.0:" | wc -l)
    if [ "$all_interface_services" -gt 0 ]; then
        add_test_result "Services on All Interfaces" "WARN" "$all_interface_services services listening on all interfaces"
    else
        add_test_result "Network Interface Binding" "PASS" "No services listening on all interfaces"
    fi
}

# DNS Configuration Security Tests  
test_dns_configuration() {
    show_loading "Checking DNS security" 6
    
    # Check DNS servers configuration
    if [ -f "/etc/resolv.conf" ]; then
        dns_servers=$(grep "^nameserver" /etc/resolv.conf | wc -l)
        add_test_result "DNS Servers Configured" "PASS" "$dns_servers DNS servers configured"
        
        # Check for secure DNS servers
        if grep -q "1.1.1.1\|8.8.8.8\|9.9.9.9" /etc/resolv.conf; then
            add_test_result "Public DNS Usage" "PASS" "Using reputable public DNS servers"
        else
            add_test_result "DNS Server Security" "INFO" "Using custom DNS servers (verify they are trusted)"
        fi
        
        # Check for DNS over HTTPS/TLS indicators
        if command -v systemd-resolve >/dev/null 2>&1; then
            if systemd-resolve --status | grep -q "DNS over TLS"; then
                add_test_result "DNS over TLS" "PASS" "DNS over TLS configured"
            else
                add_test_result "DNS over TLS" "INFO" "DNS over TLS not configured (consider for enhanced privacy)"
            fi
        fi
    else
        add_test_result "DNS Configuration" "WARN" "/etc/resolv.conf not found"
    fi
    
    # Check for DNS cache poisoning protection
    if [ -f "/etc/systemd/resolved.conf" ]; then
        if grep -q "DNSSEC=yes" /etc/systemd/resolved.conf; then
            add_test_result "DNSSEC" "PASS" "DNSSEC enabled"
        else
            add_test_result "DNSSEC" "INFO" "DNSSEC not explicitly enabled (consider for enhanced security)"
        fi
    fi
    
    # Check DNS response time (basic)
    if command -v nslookup >/dev/null 2>&1; then
        if nslookup localhost >/dev/null 2>&1; then
            add_test_result "DNS Resolution" "PASS" "DNS resolution working"
        else
            add_test_result "DNS Resolution" "WARN" "DNS resolution may have issues"
        fi
    fi
}

# Security Updates Tests
test_security_updates() {
    show_loading "Checking security updates" 7
    
    # Update package cache for accurate results
    if command -v apt >/dev/null 2>&1; then
        apt list --upgradable 2>/dev/null | grep -c "security" >/dev/null 2>&1
        security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
        security_updates=$(echo "$security_updates" | tr -d '\n')
        total_updates=$(apt list --upgradable 2>/dev/null | wc -l | tr -d '\n')
        
        if [ "$security_updates" -eq 0 ]; then
            add_test_result "Security Updates" "PASS" "System is up to date"
        else
            add_test_result "Security Updates" "FAIL" "$security_updates security updates need installation"
        fi
        
        if [ "$total_updates" -eq 0 ]; then
            add_test_result "System Updates" "PASS" "System is up to date"
        else
            add_test_result "System Updates" "WARN" "$total_updates total updates available"
        fi
        
        # Check last update time
        if [ -f "/var/log/apt/history.log" ]; then
            last_update=$(stat -c %Y /var/log/apt/history.log 2>/dev/null)
            current_time=$(date +%s)
            days_since_update=$(( (current_time - last_update) / 86400 ))
            
            if [ "$days_since_update" -lt 7 ]; then
                add_test_result "Update Frequency" "PASS" "Last updated $days_since_update days ago"
            elif [ "$days_since_update" -lt 30 ]; then
                add_test_result "Update Frequency" "WARN" "Last updated $days_since_update days ago"
            else
                add_test_result "Update Frequency" "FAIL" "Last updated $days_since_update days ago"
            fi
        fi
        
        # Check for automatic updates
        if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
            add_test_result "Automatic Security Updates" "PASS" "Automatic updates enabled"
        else
            add_test_result "Automatic Security Updates" "WARN" "Automatic updates not enabled"
        fi
    else
        add_test_result "Package Manager" "WARN" "APT package manager not found"
    fi
}

# Package Verification Tests
test_package_verification() {
    show_loading "Verifying package integrity" 6
    
    if command -v dpkg >/dev/null 2>&1; then
        # Check for broken packages
        broken_packages=$(dpkg -l 2>/dev/null | grep "^iU\|^rU" | wc -l || echo "0")
        broken_packages=$(echo "$broken_packages" | tr -d '\n')
        if [ "$broken_packages" -eq 0 ]; then
            add_test_result "Package Integrity" "PASS" "No broken packages found"
        else
            add_test_result "Package Integrity" "FAIL" "$broken_packages broken packages found"
        fi
        
        # Check package signatures (basic)
        if command -v apt-key >/dev/null 2>&1; then
            trusted_keys=$(apt-key list 2>/dev/null | grep -c "pub " || echo "0")
            add_test_result "Package Signing Keys" "PASS" "$trusted_keys trusted signing keys"
        fi
        
        # Check for packages from unknown sources
        if [ -f "/var/log/apt/history.log" ]; then
            manual_installs=$(grep -c "Install:" /var/log/apt/history.log 2>/dev/null || echo "0")
            add_test_result "Package Installation History" "PASS" "$manual_installs package installations logged"
        fi
    fi
    
    # Check repository security
    if [ -d "/etc/apt/sources.list.d/" ]; then
        ppa_count=$(find /etc/apt/sources.list.d/ -name "*.list" 2>/dev/null | wc -l | tr -d '\n')
        if [ "$ppa_count" -eq 0 ]; then
            add_test_result "Third-party Repositories" "PASS" "No third-party repositories"
        else
            add_test_result "Third-party Repositories" "WARN" "$ppa_count third-party repositories found"
        fi
    fi
    
    # Check package manager locks
    if [ -f "/var/lib/dpkg/lock" ]; then
        add_test_result "Package Manager Lock" "PASS" "Package manager lock file exists"
    else
        add_test_result "Package Manager Lock" "WARN" "Package manager lock file missing"
    fi
}

# Failed Login Attempts Tests
test_failed_login_attempts() {
    show_loading "Analyzing failed login attempts" 8
    
    # Check recent failed login attempts
    if [ -f "/var/log/auth.log" ]; then
        recent_failures=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 | wc -l | tr -d '\n')
        if [ "$recent_failures" -eq 0 ]; then
            add_test_result "Recent Failed Logins" "PASS" "No suspicious login activity"
        else
            add_test_result "Recent Failed Logins" "WARN" "$recent_failures failed login attempts detected"
        fi
        
        # Check for brute force patterns
        suspicious_ips=$(grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 5 {print $2}' | wc -l | tr -d '\n')
        if [ "$suspicious_ips" -eq 0 ]; then
            add_test_result "Brute Force Attempts" "PASS" "No suspicious IP patterns detected"
        else
            add_test_result "Brute Force Attempts" "WARN" "$suspicious_ips IPs with multiple failed attempts"
        fi
        
        # Check for successful logins after failures
        successful_after_failures=$(grep "Accepted password" /var/log/auth.log 2>/dev/null | tail -50 | wc -l | tr -d '\n')
        add_test_result "Successful Logins" "PASS" "$successful_after_failures recent successful logins"
    else
        add_test_result "Authentication Logs" "WARN" "Authentication log file not found"
    fi
    
    # Check for account lockouts
    if command -v pam_tally2 >/dev/null 2>&1; then
        locked_accounts=$(pam_tally2 --user root 2>/dev/null | grep -c "locked" || echo "0")
        locked_accounts=$(echo "$locked_accounts" | tr -d '\n')
        if [ "$locked_accounts" -eq 0 ]; then
            add_test_result "Account Lockouts" "PASS" "All accounts are accessible"
        else
            add_test_result "Account Lockouts" "WARN" "$locked_accounts accounts are locked"
        fi
    fi
    
    # Check login monitoring tools
    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban; then
            add_test_result "Fail2ban Status" "PASS" "Fail2ban is active"
            banned_ips=$(fail2ban-client status 2>/dev/null | grep -c "Currently banned:" || echo "0")
            add_test_result "Banned IPs" "PASS" "$banned_ips IPs currently banned"
        else
            add_test_result "Fail2ban Status" "WARN" "Fail2ban not active"
        fi
    else
        add_test_result "Fail2ban Installation" "WARN" "Fail2ban not installed"
    fi
}

# File Integrity Monitoring Tests
test_file_integrity_monitoring() {
    show_loading "Checking file integrity monitoring" 3
    
    # Check for important file modifications
    important_files="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config"
    for file in $important_files; do
        if [ -f "$file" ]; then
            file_age=$(find "$file" -mtime -1 2>/dev/null | wc -l | tr -d '\n')
            if [ "$file_age" -gt 0 ]; then
                add_test_result "Recent Changes: $(basename $file)" "WARN" "$(basename $file) modified in last 24 hours"
            fi
        fi
    done
    
    # Check if any file integrity tools are available (optional)
    integrity_tools_found=0
    if command -v aide >/dev/null 2>&1; then
        add_test_result "File Integrity Tools" "INFO" "AIDE is available for advanced monitoring"
        integrity_tools_found=1
    fi
    if command -v tripwire >/dev/null 2>&1; then
        add_test_result "File Integrity Tools" "INFO" "Tripwire is available for advanced monitoring"
        integrity_tools_found=1
    fi
    
    if [ "$integrity_tools_found" -eq 0 ]; then
        add_test_result "File Integrity Tools" "INFO" "No advanced file integrity tools installed (AIDE/Tripwire available)"
    fi
}

# Environment Variables Security Tests
test_environment_variables() {
    show_loading "Checking environment variables security" 5
    
    # Check for dangerous environment variables
    dangerous_vars="LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH"
    dangerous_found=0
    
    for var in $dangerous_vars; do
        if printenv | grep -q "^$var="; then
            add_test_result "Dangerous Env Var: $var" "WARN" "$var environment variable set"
            dangerous_found=$((dangerous_found + 1))
        fi
    done
    
    if [ "$dangerous_found" -eq 0 ]; then
        add_test_result "Dangerous Environment Variables" "PASS" "No dangerous environment variables found"
    fi
    
    # Check PATH security
    if echo "$PATH" | grep -q ":\.:\|:\."; then
        add_test_result "PATH Security" "FAIL" "Current directory (.) in PATH"
    else
        add_test_result "PATH Security" "PASS" "PATH does not include current directory"
    fi
    
    # Check for writable directories in PATH
    writable_path_dirs=0
    OLD_IFS="$IFS"
    IFS=':'
    for dir in $PATH; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            writable_path_dirs=$((writable_path_dirs + 1))
        fi
    done
    IFS="$OLD_IFS"
    
    # Ensure writable_path_dirs is clean number
    writable_path_dirs=$(echo "$writable_path_dirs" | tr -d '\n' | tr -d ' ')
    
    if [ "$writable_path_dirs" -eq 0 ]; then
        add_test_result "PATH Directory Permissions" "PASS" "No writable directories in PATH"
    else
        add_test_result "PATH Directory Permissions" "WARN" "$writable_path_dirs writable directories in PATH"
    fi
    
    # Check system-wide environment files
    env_files="/etc/environment /etc/profile /etc/bash.bashrc"
    for env_file in $env_files; do
        if [ -f "$env_file" ]; then
            env_perms=$(stat -c "%a" "$env_file" 2>/dev/null)
            if [ "$env_perms" = "644" ] || [ "$env_perms" = "640" ]; then
                add_test_result "Env File Permissions: $(basename $env_file)" "PASS" "Secure permissions ($env_perms)"
            else
                add_test_result "Env File Permissions: $(basename $env_file)" "WARN" "Permissions: $env_perms"
            fi
        fi
    done
}

# Temporary Files Security Tests
test_temporary_files_security() {
    show_loading "Checking temporary files security" 7
    
    # Check /tmp permissions and mount options
    tmp_perms=$(stat -c "%a" /tmp 2>/dev/null)
    if [ "$tmp_perms" = "1777" ]; then
        add_test_result "/tmp Permissions" "PASS" "Sticky bit set on /tmp"
    else
        add_test_result "/tmp Permissions" "WARN" "/tmp permissions: $tmp_perms"
    fi
    
    # Check /tmp mount options
    if mount | grep " /tmp " | grep -q "noexec"; then
        add_test_result "/tmp Mount Options" "PASS" "/tmp mounted with noexec"
    else
        add_test_result "/tmp Mount Options" "WARN" "/tmp not mounted with noexec"
    fi
    
    # Check /var/tmp permissions
    if [ -d "/var/tmp" ]; then
        vartmp_perms=$(stat -c "%a" /var/tmp 2>/dev/null)
        if [ "$vartmp_perms" = "1777" ]; then
            add_test_result "/var/tmp Permissions" "PASS" "Sticky bit set on /var/tmp"
        else
            add_test_result "/var/tmp Permissions" "WARN" "/var/tmp permissions: $vartmp_perms"
        fi
    fi
    
    # Check for old temporary files
    old_tmp_files=$(find /tmp -type f -mtime +7 2>/dev/null | wc -l | tr -d '\n')
    if [ "$old_tmp_files" -eq 0 ]; then
        add_test_result "Old Temporary Files" "PASS" "No old files in /tmp"
    else
        add_test_result "Old Temporary Files" "WARN" "$old_tmp_files files older than 7 days in /tmp"
    fi
    
    # Check temporary file cleanup configuration
    if systemctl list-unit-files | grep -q "systemd-tmpfiles"; then
        add_test_result "Temporary File Cleanup" "PASS" "systemd-tmpfiles service available"
    else
        add_test_result "Temporary File Cleanup" "WARN" "No automatic temp file cleanup configured"
    fi
    
    # Check for large files in /tmp
    large_tmp_files=$(find /tmp -type f -size +100M 2>/dev/null | wc -l | tr -d '\n')
    if [ "$large_tmp_files" -eq 0 ]; then
        add_test_result "Large Temporary Files" "PASS" "No large files in /tmp"
    else
        add_test_result "Large Temporary Files" "WARN" "$large_tmp_files large files in /tmp"
    fi
    
    # Check world-writable files in temp directories
    world_writable=$(find /tmp /var/tmp -type f -perm -002 2>/dev/null | wc -l | tr -d '\n')
    if [ "$world_writable" -eq 0 ]; then
        add_test_result "World-writable Temp Files" "PASS" "No world-writable files in temp directories"
    else
        add_test_result "World-writable Temp Files" "WARN" "$world_writable world-writable files in temp directories"
    fi
}

# Web Server Specialized Tests
test_web_server_security() {
    show_loading "Analyzing web server security" 35
    
    # Apache Security Tests
    if systemctl is-active --quiet apache2 2>/dev/null; then
        add_test_result "Apache Service Status" "PASS" "Apache is running"
        
        # Apache version and modules
        if command -v apache2 >/dev/null 2>&1; then
            apache_version=$(apache2 -v 2>/dev/null | head -1)
            add_test_result "Apache Version" "PASS" "$apache_version"
        fi
        
        # Check Apache security configuration
        apache_conf="/etc/apache2/apache2.conf"
        if [ -f "$apache_conf" ]; then
            # Server tokens
            if grep -q "^ServerTokens.*Prod" /etc/apache2/conf-available/security.conf 2>/dev/null; then
                add_test_result "Apache ServerTokens" "PASS" "ServerTokens set to Prod"
            else
                add_test_result "Apache ServerTokens" "WARN" "ServerTokens not configured securely"
            fi
            
            # Server signature
            if grep -q "^ServerSignature.*Off" /etc/apache2/conf-available/security.conf 2>/dev/null; then
                add_test_result "Apache ServerSignature" "PASS" "ServerSignature disabled"
            else
                add_test_result "Apache ServerSignature" "WARN" "ServerSignature not disabled"
            fi
            
            # Directory indexing
            if grep -q "Options.*-Indexes" /etc/apache2/apache2.conf 2>/dev/null; then
                add_test_result "Apache Directory Indexing" "PASS" "Directory indexing disabled"
            else
                add_test_result "Apache Directory Indexing" "WARN" "Directory indexing not explicitly disabled"
            fi
        fi
        
        # Check for dangerous modules
        dangerous_modules="mod_info mod_status mod_userdir"
        for module in $dangerous_modules; do
            if apache2ctl -M 2>/dev/null | grep -q "$module"; then
                add_test_result "Apache Module: $module" "WARN" "$module enabled (review if needed)"
            else
                add_test_result "Apache Module: $module" "PASS" "$module disabled"
            fi
        done
        
        # Check if mod_security is available
        if apache2ctl -M 2>/dev/null | grep -q "security2_module"; then
            add_test_result "Apache ModSecurity" "PASS" "ModSecurity module loaded"
        else
            add_test_result "Apache ModSecurity" "INFO" "ModSecurity not installed (consider for enhanced security)"
        fi
    fi
    
    # Nginx Security Tests
    if systemctl is-active --quiet nginx 2>/dev/null; then
        add_test_result "Nginx Service Status" "PASS" "Nginx is running"
        
        # Nginx user
        nginx_user=$(ps aux | grep nginx | grep -v root | head -1 | awk '{print $1}')
        if [ "$nginx_user" != "root" ] && [ ! -z "$nginx_user" ]; then
            add_test_result "Nginx User Security" "PASS" "Nginx running as: $nginx_user"
        else
            add_test_result "Nginx User Security" "WARN" "Nginx user configuration needs review"
        fi
        
        # Check nginx configuration
        nginx_conf="/etc/nginx/nginx.conf"
        if [ -f "$nginx_conf" ]; then
            # Server tokens
            if grep -q "server_tokens.*off" "$nginx_conf"; then
                add_test_result "Nginx Server Tokens" "PASS" "Server tokens disabled"
            else
                add_test_result "Nginx Server Tokens" "WARN" "Server tokens not disabled"
            fi
            
            # Check for autoindex off
            if grep -q "autoindex.*off" "$nginx_conf" /etc/nginx/sites-enabled/* 2>/dev/null; then
                add_test_result "Nginx Directory Indexing" "PASS" "Directory indexing disabled"
            else
                add_test_result "Nginx Directory Indexing" "INFO" "Directory indexing setting not found (verify configuration)"
            fi
        fi
    fi
    
    # Web Root Directory Security
    web_roots="/var/www /usr/share/nginx/html"
    for web_root in $web_roots; do
        if [ -d "$web_root" ]; then
            web_perms=$(stat -c "%a" "$web_root" 2>/dev/null)
            if [ "$web_perms" = "755" ] || [ "$web_perms" = "750" ]; then
                add_test_result "Web Root Permissions: $(basename $web_root)" "PASS" "Secure permissions ($web_perms)"
            else
                add_test_result "Web Root Permissions: $(basename $web_root)" "WARN" "Permissions: $web_perms"
            fi
            
            # Check for sensitive files in web root
            sensitive_files=".env .git .htaccess config.php wp-config.php"
            found_sensitive=0
            for file in $sensitive_files; do
                if find "$web_root" -name "$file" -type f 2>/dev/null | grep -q .; then
                    add_test_result "Sensitive File: $file" "WARN" "$file found in web directory"
                    found_sensitive=1
                fi
            done
            
            if [ "$found_sensitive" -eq 0 ]; then
                add_test_result "Sensitive Files Check" "PASS" "No obvious sensitive files in web root"
            fi
            
            # Check for backup files
            backup_files=$(find "$web_root" -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~" 2>/dev/null | wc -l)
            if [ "$backup_files" -eq 0 ]; then
                add_test_result "Backup Files Check" "PASS" "No backup files in web directory"
            else
                add_test_result "Backup Files Check" "WARN" "$backup_files backup files found in web directory"
            fi
        fi
    done
    
    # SSL/TLS Configuration Security
    if [ -d "/etc/ssl/certs" ]; then
        ssl_certs=$(find /etc/ssl/certs -name "*.crt" -o -name "*.pem" | wc -l)
        add_test_result "SSL Certificates" "PASS" "$ssl_certs SSL certificates found"
        
        # Check for HTTPS redirect configuration
        if systemctl is-active --quiet apache2 2>/dev/null; then
            if grep -r "Redirect.*https" /etc/apache2/sites-enabled/ 2>/dev/null | grep -q .; then
                add_test_result "HTTPS Redirect" "PASS" "HTTPS redirect configured"
            else
                add_test_result "HTTPS Redirect" "INFO" "HTTPS redirect not found (verify configuration)"
            fi
        elif systemctl is-active --quiet nginx 2>/dev/null; then
            if grep -r "return.*https" /etc/nginx/sites-enabled/ 2>/dev/null | grep -q .; then
                add_test_result "HTTPS Redirect" "PASS" "HTTPS redirect configured"
            else
                add_test_result "HTTPS Redirect" "INFO" "HTTPS redirect not found (verify configuration)"
            fi
        fi
    fi
    
    # PHP Security (if PHP is installed)
    if command -v php >/dev/null 2>&1; then
        php_version=$(php -r "echo PHP_VERSION;" 2>/dev/null)
        add_test_result "PHP Installation" "PASS" "PHP version: $php_version"
        
        # Check PHP configuration
        php_ini=$(php --ini 2>/dev/null | grep "Loaded Configuration File" | cut -d: -f2 | tr -d ' ')
        if [ -f "$php_ini" ]; then
            # expose_php
            if grep -q "^expose_php.*Off" "$php_ini" 2>/dev/null; then
                add_test_result "PHP expose_php" "PASS" "PHP version hiding enabled"
            else
                add_test_result "PHP expose_php" "WARN" "PHP version not hidden"
            fi
            
            # display_errors
            if grep -q "^display_errors.*Off" "$php_ini" 2>/dev/null; then
                add_test_result "PHP display_errors" "PASS" "Error display disabled"
            else
                add_test_result "PHP display_errors" "WARN" "Error display not disabled"
            fi
            
            # allow_url_fopen
            if grep -q "^allow_url_fopen.*Off" "$php_ini" 2>/dev/null; then
                add_test_result "PHP allow_url_fopen" "PASS" "Remote file access disabled"
            else
                add_test_result "PHP allow_url_fopen" "WARN" "Remote file access not disabled"
            fi
        fi
    fi
    
    # Node.js Security (if Node.js is installed)
    if command -v node >/dev/null 2>&1; then
        node_version=$(node --version 2>/dev/null)
        add_test_result "Node.js Installation" "PASS" "Node.js version: $node_version"
        
        # Check for PM2 process manager
        if command -v pm2 >/dev/null 2>&1; then
            add_test_result "Node.js Process Manager" "PASS" "PM2 process manager available"
        else
            add_test_result "Node.js Process Manager" "WARN" "No process manager detected (consider PM2 for production)"
        fi
        
        # Check if Node.js is running as root
        node_processes=$(ps aux | grep node | grep -v grep | grep -v root | wc -l)
        if [ "$node_processes" -gt 0 ]; then
            add_test_result "Node.js User Security" "PASS" "Node.js processes not running as root"
        else
            node_root_processes=$(ps aux | grep node | grep -v grep | grep root | wc -l)
            if [ "$node_root_processes" -gt 0 ]; then
                add_test_result "Node.js User Security" "WARN" "Node.js processes running as root"
            fi
        fi
    fi
    
    # Common HTTP Security Headers Check (basic test)
    if command -v curl >/dev/null 2>&1; then
        # Try to check localhost for security headers
        if curl -sI http://localhost 2>/dev/null | grep -q "Server:"; then
            # X-Frame-Options
            if curl -sI http://localhost 2>/dev/null | grep -q "X-Frame-Options"; then
                add_test_result "HTTP Security Headers" "PASS" "X-Frame-Options header present"
            else
                add_test_result "HTTP Security Headers" "WARN" "X-Frame-Options header missing"
            fi
            
            # X-XSS-Protection
            if curl -sI http://localhost 2>/dev/null | grep -q "X-XSS-Protection"; then
                add_test_result "XSS Protection Header" "PASS" "X-XSS-Protection header present"
            else
                add_test_result "XSS Protection Header" "WARN" "X-XSS-Protection header missing"
            fi
        else
            add_test_result "HTTP Security Headers" "INFO" "Cannot test security headers (no local web response)"
        fi
    fi
    
    # MySQL Security Tests (if MySQL is installed)
    if command -v mysql >/dev/null 2>&1 || systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null; then
        mysql_version=$(mysql --version 2>/dev/null | awk '{print $1,$2,$3}' || echo "MySQL detected")
        add_test_result "MySQL Installation" "PASS" "$mysql_version"
        
        # Check if MySQL is running
        if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null; then
            add_test_result "MySQL Service Status" "PASS" "MySQL service is running"
            
            # Check MySQL configuration
            mysql_conf="/etc/mysql/mysql.conf.d/mysqld.cnf"
            mysql_conf_alt="/etc/my.cnf"
            mysql_config=""
            
            if [ -f "$mysql_conf" ]; then
                mysql_config="$mysql_conf"
            elif [ -f "$mysql_conf_alt" ]; then
                mysql_config="$mysql_conf_alt"
            fi
            
            if [ ! -z "$mysql_config" ]; then
                # Check bind-address
                if grep -q "^bind-address.*127.0.0.1" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Bind Address" "PASS" "MySQL bound to localhost only"
                elif grep -q "^bind-address.*0.0.0.0" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Bind Address" "WARN" "MySQL bound to all interfaces"
                else
                    add_test_result "MySQL Bind Address" "INFO" "MySQL bind address not explicitly configured"
                fi
                
                # Check skip-networking
                if grep -q "^skip-networking" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Network Access" "PASS" "Network access disabled"
                else
                    add_test_result "MySQL Network Access" "INFO" "Network access enabled (verify if needed)"
                fi
                
                # Check log settings
                if grep -q "^log-error" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Error Logging" "PASS" "Error logging configured"
                else
                    add_test_result "MySQL Error Logging" "WARN" "Error logging not configured"
                fi
                
                # Check general log
                if grep -q "^general_log.*ON" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL General Logging" "PASS" "General logging enabled"
                else
                    add_test_result "MySQL General Logging" "INFO" "General logging disabled (enable for security auditing)"
                fi
                
                # Check binary logging
                if grep -q "^log-bin" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Binary Logging" "PASS" "Binary logging enabled"
                else
                    add_test_result "MySQL Binary Logging" "INFO" "Binary logging not configured"
                fi
            fi
            
            # Check MySQL process user
            mysql_user=$(ps aux | grep mysql | grep -v grep | grep -v root | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$mysql_user" = "mysql" ]; then
                add_test_result "MySQL Process User" "PASS" "MySQL running as mysql user"
            elif [ ! -z "$mysql_user" ] && [ "$mysql_user" != "root" ]; then
                add_test_result "MySQL Process User" "PASS" "MySQL running as: $mysql_user"
            else
                add_test_result "MySQL Process User" "WARN" "MySQL may be running as root"
            fi
            
            # Check MySQL port
            if netstat -tlnp 2>/dev/null | grep -q ":3306.*mysql"; then
                add_test_result "MySQL Port Security" "PASS" "MySQL running on standard port 3306"
            elif netstat -tlnp 2>/dev/null | grep mysql | grep -q ":"; then
                mysql_port=$(netstat -tlnp 2>/dev/null | grep mysql | awk '{print $4}' | cut -d: -f2)
                add_test_result "MySQL Port Security" "INFO" "MySQL running on custom port: $mysql_port"
            fi
        else
            add_test_result "MySQL Service Status" "INFO" "MySQL service not running"
        fi
    else
        add_test_result "MySQL Database" "INFO" "MySQL not installed"
    fi
    
    # MongoDB Security Tests (if MongoDB is installed)
    if command -v mongod >/dev/null 2>&1 || systemctl is-active --quiet mongod 2>/dev/null || command -v mongo >/dev/null 2>&1; then
        mongo_version=$(mongod --version 2>/dev/null | head -1 | cut -d' ' -f3 || echo "MongoDB detected")
        add_test_result "MongoDB Installation" "PASS" "MongoDB version: $mongo_version"
        
        # Check if MongoDB is running
        if systemctl is-active --quiet mongod 2>/dev/null || pgrep mongod >/dev/null 2>&1; then
            add_test_result "MongoDB Service Status" "PASS" "MongoDB service is running"
            
            # Check MongoDB configuration
            mongo_conf="/etc/mongod.conf"
            if [ -f "$mongo_conf" ]; then
                # Check bind IP
                if grep -q "bindIp.*127.0.0.1" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Bind IP" "PASS" "MongoDB bound to localhost only"
                elif grep -q "bindIp.*0.0.0.0" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Bind IP" "WARN" "MongoDB bound to all interfaces"
                else
                    add_test_result "MongoDB Bind IP" "INFO" "MongoDB bind IP not explicitly configured"
                fi
                
                # Check authentication
                if grep -q "authorization.*enabled" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Authentication" "PASS" "Authentication enabled"
                else
                    add_test_result "MongoDB Authentication" "FAIL" "Authentication not enabled - CRITICAL RISK"
                fi
                
                # Check SSL/TLS
                if grep -q "ssl:" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB SSL/TLS" "PASS" "SSL/TLS configuration found"
                else
                    add_test_result "MongoDB SSL/TLS" "WARN" "SSL/TLS not configured"
                fi
                
                # Check logging
                if grep -q "destination.*file" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Logging" "PASS" "File logging configured"
                else
                    add_test_result "MongoDB Logging" "WARN" "File logging not configured"
                fi
            else
                add_test_result "MongoDB Configuration" "WARN" "MongoDB configuration file not found"
            fi
            
            # Check MongoDB process user
            mongo_user=$(ps aux | grep mongod | grep -v grep | grep -v root | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$mongo_user" = "mongodb" ] || [ "$mongo_user" = "mongod" ]; then
                add_test_result "MongoDB Process User" "PASS" "MongoDB running as: $mongo_user"
            elif [ ! -z "$mongo_user" ] && [ "$mongo_user" != "root" ]; then
                add_test_result "MongoDB Process User" "PASS" "MongoDB running as: $mongo_user"
            else
                add_test_result "MongoDB Process User" "WARN" "MongoDB may be running as root"
            fi
            
            # Check MongoDB port
            if netstat -tlnp 2>/dev/null | grep -q ":27017.*mongod"; then
                add_test_result "MongoDB Port Security" "PASS" "MongoDB running on standard port 27017"
            elif netstat -tlnp 2>/dev/null | grep mongod | grep -q ":"; then
                mongo_port=$(netstat -tlnp 2>/dev/null | grep mongod | awk '{print $4}' | cut -d: -f2)
                add_test_result "MongoDB Port Security" "INFO" "MongoDB running on custom port: $mongo_port"
            fi
        else
            add_test_result "MongoDB Service Status" "INFO" "MongoDB service not running"
        fi
    else
        add_test_result "MongoDB Database" "INFO" "MongoDB not installed"
    fi
    
    # Check for common web ports
    web_ports="80 443 8080 8443"
    for port in $web_ports; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            service_name=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f2)
            add_test_result "Web Port $port" "PASS" "Port $port open - $service_name"
        fi
    done
}

# Database Server Specialized Tests
test_database_security() {
    show_loading "Analyzing database server security" 50
    
    # MySQL/MariaDB Security Tests
    if command -v mysql >/dev/null 2>&1 || systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; then
        if command -v mysql >/dev/null 2>&1; then
            mysql_version=$(mysql --version 2>/dev/null | awk '{print $1,$2,$3}' || echo "MySQL/MariaDB detected")
            add_test_result "MySQL/MariaDB Installation" "PASS" "$mysql_version"
        fi
        
        # Check if MySQL/MariaDB is running
        if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; then
            add_test_result "MySQL/MariaDB Service" "PASS" "Database service is running"
            
            # MySQL configuration files
            mysql_configs="/etc/mysql/mysql.conf.d/mysqld.cnf /etc/my.cnf /etc/mysql/my.cnf"
            mysql_config=""
            for conf in $mysql_configs; do
                if [ -f "$conf" ]; then
                    mysql_config="$conf"
                    break
                fi
            done
            
            if [ ! -z "$mysql_config" ]; then
                # Bind address security (CRITICAL)
                if grep -q "^bind-address.*127.0.0.1" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Bind Address" "PASS" "Bound to localhost only"
                elif grep -q "^bind-address.*0.0.0.0" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Bind Address" "FAIL" "Bound to all interfaces - CRITICAL RISK"
                else
                    add_test_result "MySQL Bind Address" "WARN" "Bind address not explicitly set"
                fi
                
                # Skip networking (HIGHEST SECURITY)
                if grep -q "^skip-networking" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Network Isolation" "PASS" "Network access completely disabled"
                else
                    add_test_result "MySQL Network Isolation" "WARN" "Network access enabled - verify security"
                fi
                
                # SSL/TLS Configuration
                if grep -q "^ssl-ca\|^ssl-cert\|^ssl-key" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL SSL/TLS" "PASS" "SSL certificates configured"
                    
                    # Check if SSL is required
                    if grep -q "^require_secure_transport.*ON" "$mysql_config" 2>/dev/null; then
                        add_test_result "MySQL SSL Enforcement" "PASS" "SSL connections required"
                    else
                        add_test_result "MySQL SSL Enforcement" "WARN" "SSL not enforced for all connections"
                    fi
                else
                    add_test_result "MySQL SSL/TLS" "FAIL" "SSL/TLS not configured - data transmitted in plaintext"
                fi
                
                # Logging Configuration (CRITICAL FOR AUDITING)
                if grep -q "^log-error" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Error Logging" "PASS" "Error logging enabled"
                else
                    add_test_result "MySQL Error Logging" "FAIL" "Error logging not configured - security incidents untracked"
                fi
                
                if grep -q "^general_log.*ON\|^general_log.*1" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL General Logging" "PASS" "General logging enabled for auditing"
                else
                    add_test_result "MySQL General Logging" "WARN" "General logging disabled (enable for security auditing)"
                fi
                
                if grep -q "^log-bin" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Binary Logging" "PASS" "Binary logging enabled for recovery"
                else
                    add_test_result "MySQL Binary Logging" "WARN" "Binary logging not configured"
                fi
                
                if grep -q "^slow_query_log.*ON\|^slow_query_log.*1" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Slow Query Log" "PASS" "Slow query logging enabled"
                else
                    add_test_result "MySQL Slow Query Log" "WARN" "Slow query logging disabled"
                fi
                
                # Security-Critical Settings
                if grep -q "^local-infile.*0" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Local Infile" "PASS" "Local file loading disabled"
                else
                    add_test_result "MySQL Local Infile" "FAIL" "Local file loading enabled - security risk"
                fi
                
                if grep -q "^symbolic-links.*0" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Symbolic Links" "PASS" "Symbolic links disabled"
                else
                    add_test_result "MySQL Symbolic Links" "WARN" "Symbolic links not disabled"
                fi
                
                # Dangerous functions disabled
                if grep -q "^sql_mode.*STRICT_TRANS_TABLES" "$mysql_config" 2>/dev/null; then
                    add_test_result "MySQL Strict Mode" "PASS" "Strict SQL mode enabled"
                else
                    add_test_result "MySQL Strict Mode" "WARN" "Strict SQL mode not enabled"
                fi
                
                # User limits
                if grep -q "^max_connections" "$mysql_config" 2>/dev/null; then
                    max_conn=$(grep "^max_connections" "$mysql_config" | awk '{print $3}' | tr -d '=')
                    if [ "$max_conn" -le 200 ]; then
                        add_test_result "MySQL Connection Limit" "PASS" "Connection limit: $max_conn"
                    else
                        add_test_result "MySQL Connection Limit" "WARN" "High connection limit: $max_conn"
                    fi
                else
                    add_test_result "MySQL Connection Limit" "WARN" "Connection limit not explicitly set"
                fi
            else
                add_test_result "MySQL Configuration" "FAIL" "Configuration file not found - cannot verify security"
            fi
            
            # Process user check (CRITICAL)
            mysql_user=$(ps aux | grep -E "mysql|mariadb" | grep -v grep | grep -v root | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$mysql_user" = "mysql" ] || [ "$mysql_user" = "mariadb" ]; then
                add_test_result "MySQL Process User" "PASS" "Running as dedicated user: $mysql_user"
            elif [ ! -z "$mysql_user" ] && [ "$mysql_user" != "root" ]; then
                add_test_result "MySQL Process User" "PASS" "Running as: $mysql_user"
            else
                add_test_result "MySQL Process User" "FAIL" "Running as root - CRITICAL SECURITY RISK"
            fi
            
            # Port and network security
            if netstat -tlnp 2>/dev/null | grep -q ":3306.*mysql\|:3306.*mariadb"; then
                port_binding=$(netstat -tlnp 2>/dev/null | grep ":3306" | awk '{print $4}' | head -1)
                if echo "$port_binding" | grep -q "127.0.0.1:3306"; then
                    add_test_result "MySQL Port Security" "PASS" "Port 3306 bound to localhost only"
                elif echo "$port_binding" | grep -q "0.0.0.0:3306"; then
                    add_test_result "MySQL Port Security" "FAIL" "Port 3306 accessible from any IP - CRITICAL RISK"
                else
                    add_test_result "MySQL Port Security" "PASS" "Port 3306 bound to: $port_binding"
                fi
            elif netstat -tlnp 2>/dev/null | grep -E "mysql|mariadb" | grep -q ":"; then
                mysql_port=$(netstat -tlnp 2>/dev/null | grep -E "mysql|mariadb" | awk '{print $4}' | cut -d: -f2 | head -1)
                add_test_result "MySQL Custom Port" "PASS" "Running on custom port: $mysql_port"
            fi
            
            # Data directory security (CRITICAL)
            mysql_datadir="/var/lib/mysql"
            if [ -d "$mysql_datadir" ]; then
                datadir_perms=$(stat -c "%a" "$mysql_datadir" 2>/dev/null)
                datadir_owner=$(stat -c "%U" "$mysql_datadir" 2>/dev/null)
                
                if [ "$datadir_perms" = "755" ] || [ "$datadir_perms" = "750" ] || [ "$datadir_perms" = "700" ]; then
                    add_test_result "MySQL Data Directory Perms" "PASS" "Secure permissions ($datadir_perms)"
                else
                    add_test_result "MySQL Data Directory Perms" "FAIL" "Insecure permissions: $datadir_perms"
                fi
                
                if [ "$datadir_owner" = "mysql" ] || [ "$datadir_owner" = "mariadb" ]; then
                    add_test_result "MySQL Data Directory Owner" "PASS" "Owned by database user: $datadir_owner"
                else
                    add_test_result "MySQL Data Directory Owner" "FAIL" "Wrong ownership: $datadir_owner"
                fi
            fi
            
            # MySQL-specific security checks
            mysql_secure_files="/var/lib/mysql/.mysql_history"
            if [ -f "$mysql_secure_files" ]; then
                add_test_result "MySQL History File" "WARN" "MySQL history file exists (may contain passwords)"
            else
                add_test_result "MySQL History File" "PASS" "No MySQL history file found"
            fi
        else
            add_test_result "MySQL/MariaDB Service" "WARN" "Database service not running"
        fi
    else
        add_test_result "MySQL/MariaDB" "INFO" "MySQL/MariaDB not installed"
    fi
    
    # PostgreSQL Security Tests (COMPREHENSIVE)
    if command -v psql >/dev/null 2>&1 || systemctl is-active --quiet postgresql 2>/dev/null; then
        if command -v psql >/dev/null 2>&1; then
            pg_version=$(psql --version 2>/dev/null | awk '{print $1,$2,$3}' || echo "PostgreSQL detected")
            add_test_result "PostgreSQL Installation" "PASS" "$pg_version"
        fi
        
        # Check if PostgreSQL is running
        if systemctl is-active --quiet postgresql 2>/dev/null || pgrep postgres >/dev/null 2>&1; then
            add_test_result "PostgreSQL Service" "PASS" "PostgreSQL service is running"
            
            # PostgreSQL configuration
            pg_config_paths="/etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf"
            pg_config=""
            for conf_path in $pg_config_paths; do
                if ls $conf_path 2>/dev/null | head -1 | grep -q .; then
                    pg_config=$(ls $conf_path 2>/dev/null | head -1)
                    break
                fi
            done
            
            if [ ! -z "$pg_config" ] && [ -f "$pg_config" ]; then
                # Listen addresses (CRITICAL)
                if grep -q "^listen_addresses.*'localhost'" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Listen Address" "PASS" "Listening on localhost only"
                elif grep -q "^listen_addresses.*'\*'" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Listen Address" "FAIL" "Listening on all interfaces - CRITICAL RISK"
                else
                    add_test_result "PostgreSQL Listen Address" "WARN" "Listen address not explicitly configured"
                fi
                
                # SSL configuration (CRITICAL)
                if grep -q "^ssl.*on" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL SSL" "PASS" "SSL encryption enabled"
                    
                    # SSL enforcement
                    if grep -q "^ssl_prefer_server_ciphers.*on" "$pg_config" 2>/dev/null; then
                        add_test_result "PostgreSQL SSL Ciphers" "PASS" "Server SSL ciphers preferred"
                    else
                        add_test_result "PostgreSQL SSL Ciphers" "WARN" "SSL cipher preference not configured"
                    fi
                else
                    add_test_result "PostgreSQL SSL" "FAIL" "SSL not enabled - data transmitted in plaintext"
                fi
                
                # Logging configuration (CRITICAL FOR AUDITING)
                if grep -q "^log_statement.*'all'\|^log_statement.*'ddl'" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Statement Logging" "PASS" "SQL statement logging enabled"
                else
                    add_test_result "PostgreSQL Statement Logging" "FAIL" "Statement logging disabled - security incidents untracked"
                fi
                
                if grep -q "^log_connections.*on" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Connection Logging" "PASS" "Connection logging enabled"
                else
                    add_test_result "PostgreSQL Connection Logging" "WARN" "Connection logging disabled"
                fi
                
                if grep -q "^log_disconnections.*on" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Disconnection Logging" "PASS" "Disconnection logging enabled"
                else
                    add_test_result "PostgreSQL Disconnection Logging" "WARN" "Disconnection logging disabled"
                fi
                
                if grep -q "^log_lock_waits.*on" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Lock Wait Logging" "PASS" "Lock wait logging enabled"
                else
                    add_test_result "PostgreSQL Lock Wait Logging" "WARN" "Lock wait logging disabled"
                fi
                
                # Security settings
                if grep -q "^shared_preload_libraries.*'pg_stat_statements'" "$pg_config" 2>/dev/null; then
                    add_test_result "PostgreSQL Query Statistics" "PASS" "Query statistics tracking enabled"
                else
                    add_test_result "PostgreSQL Query Statistics" "WARN" "Query statistics not enabled"
                fi
                
                # Connection limits
                max_conn=$(grep "^max_connections" "$pg_config" 2>/dev/null | awk '{print $3}')
                if [ ! -z "$max_conn" ]; then
                    if [ "$max_conn" -le 200 ]; then
                        add_test_result "PostgreSQL Connection Limit" "PASS" "Connection limit: $max_conn"
                    else
                        add_test_result "PostgreSQL Connection Limit" "WARN" "High connection limit: $max_conn"
                    fi
                else
                    add_test_result "PostgreSQL Connection Limit" "WARN" "Connection limit not explicitly set"
                fi
            else
                add_test_result "PostgreSQL Configuration" "FAIL" "Configuration file not found"
            fi
            
            # HBA configuration (AUTHENTICATION - CRITICAL)
            pg_hba_paths="/etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf"
            pg_hba=""
            for hba_path in $pg_hba_paths; do
                if ls $hba_path 2>/dev/null | head -1 | grep -q .; then
                    pg_hba=$(ls $hba_path 2>/dev/null | head -1)
                    break
                fi
            done
            
            if [ ! -z "$pg_hba" ] && [ -f "$pg_hba" ]; then
                # Check for trust authentication (CRITICAL VULNERABILITY)
                trust_count=$(grep -c "trust" "$pg_hba" 2>/dev/null || echo "0")
                if [ "$trust_count" -gt 0 ]; then
                    add_test_result "PostgreSQL Trust Authentication" "FAIL" "$trust_count trust authentication entries - CRITICAL RISK"
                else
                    add_test_result "PostgreSQL Trust Authentication" "PASS" "No trust authentication found"
                fi
                
                # Check for password authentication
                if grep -q "md5\|scram-sha-256" "$pg_hba" 2>/dev/null; then
                    add_test_result "PostgreSQL Password Auth" "PASS" "Encrypted password authentication configured"
                else
                    add_test_result "PostgreSQL Password Auth" "WARN" "Encrypted password authentication not found"
                fi
                
                # Check for peer authentication (local connections)
                if grep -q "peer\|ident" "$pg_hba" 2>/dev/null; then
                    add_test_result "PostgreSQL Local Auth" "PASS" "Peer/ident authentication for local connections"
                else
                    add_test_result "PostgreSQL Local Auth" "WARN" "Local authentication method not configured"
                fi
            else
                add_test_result "PostgreSQL HBA Configuration" "FAIL" "pg_hba.conf not found - authentication unconfigured"
            fi
            
            # Process user check (CRITICAL)
            pg_user=$(ps aux | grep postgres | grep -v grep | grep -v root | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$pg_user" = "postgres" ]; then
                add_test_result "PostgreSQL Process User" "PASS" "Running as postgres user"
            elif [ ! -z "$pg_user" ] && [ "$pg_user" != "root" ]; then
                add_test_result "PostgreSQL Process User" "PASS" "Running as: $pg_user"
            else
                add_test_result "PostgreSQL Process User" "FAIL" "Running as root - CRITICAL SECURITY RISK"
            fi
            
            # Port security
            if netstat -tlnp 2>/dev/null | grep -q ":5432.*postgres"; then
                port_binding=$(netstat -tlnp 2>/dev/null | grep ":5432" | awk '{print $4}' | head -1)
                if echo "$port_binding" | grep -q "127.0.0.1:5432"; then
                    add_test_result "PostgreSQL Port Security" "PASS" "Port 5432 bound to localhost only"
                elif echo "$port_binding" | grep -q "0.0.0.0:5432"; then
                    add_test_result "PostgreSQL Port Security" "FAIL" "Port 5432 accessible from any IP - CRITICAL RISK"
                else
                    add_test_result "PostgreSQL Port Security" "PASS" "Port 5432 bound to: $port_binding"
                fi
            elif netstat -tlnp 2>/dev/null | grep postgres | grep -q ":"; then
                pg_port=$(netstat -tlnp 2>/dev/null | grep postgres | awk '{print $4}' | cut -d: -f2 | head -1)
                add_test_result "PostgreSQL Custom Port" "PASS" "Running on custom port: $pg_port"
            fi
            
            # Data directory security
            pg_datadir="/var/lib/postgresql"
            if [ -d "$pg_datadir" ]; then
                datadir_perms=$(stat -c "%a" "$pg_datadir" 2>/dev/null)
                datadir_owner=$(stat -c "%U" "$pg_datadir" 2>/dev/null)
                
                if [ "$datadir_perms" = "755" ] || [ "$datadir_perms" = "750" ] || [ "$datadir_perms" = "700" ]; then
                    add_test_result "PostgreSQL Data Directory Perms" "PASS" "Secure permissions ($datadir_perms)"
                else
                    add_test_result "PostgreSQL Data Directory Perms" "FAIL" "Insecure permissions: $datadir_perms"
                fi
                
                if [ "$datadir_owner" = "postgres" ]; then
                    add_test_result "PostgreSQL Data Directory Owner" "PASS" "Owned by postgres user"
                else
                    add_test_result "PostgreSQL Data Directory Owner" "FAIL" "Wrong ownership: $datadir_owner"
                fi
            fi
        else
            add_test_result "PostgreSQL Service" "WARN" "PostgreSQL service not running"
        fi
    else
        add_test_result "PostgreSQL" "INFO" "PostgreSQL not installed"
    fi
    
    # MongoDB Security Tests (ENHANCED AND CRITICAL)
    if command -v mongod >/dev/null 2>&1 || systemctl is-active --quiet mongod 2>/dev/null || command -v mongo >/dev/null 2>&1; then
        mongo_version=$(mongod --version 2>/dev/null | head -1 | cut -d' ' -f3 || echo "MongoDB detected")
        add_test_result "MongoDB Installation" "PASS" "MongoDB version: $mongo_version"
        
        # Check if MongoDB is running
        if systemctl is-active --quiet mongod 2>/dev/null || pgrep mongod >/dev/null 2>&1; then
            add_test_result "MongoDB Service" "PASS" "MongoDB service is running"
            
            # MongoDB configuration (CRITICAL)
            mongo_conf="/etc/mongod.conf"
            if [ -f "$mongo_conf" ]; then
                # Bind IP security (MOST CRITICAL)
                if grep -q "bindIp.*127.0.0.1" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Bind IP" "PASS" "Bound to localhost only"
                elif grep -q "bindIp.*0.0.0.0" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Bind IP" "FAIL" "Bound to all interfaces - CRITICAL RISK"
                else
                    add_test_result "MongoDB Bind IP" "FAIL" "Bind IP not configured - default allows external access"
                fi
                
                # Authentication (CRITICAL - MongoDB default is NO AUTH!)
                if grep -q "authorization.*enabled" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Authentication" "PASS" "Authentication enabled"
                else
                    add_test_result "MongoDB Authentication" "FAIL" "Authentication disabled - CRITICAL RISK"
                fi
                
                # SSL/TLS configuration
                if grep -q "ssl:" "$mongo_conf" 2>/dev/null && grep -q "mode.*requireSSL" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB SSL/TLS" "PASS" "SSL required for all connections"
                elif grep -q "ssl:" "$mongo_conf" 2>/dev/null && grep -q "mode.*preferSSL" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB SSL/TLS" "WARN" "SSL preferred but not required"
                elif grep -q "ssl:" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB SSL/TLS" "WARN" "SSL configured but not enforced"
                else
                    add_test_result "MongoDB SSL/TLS" "FAIL" "SSL/TLS not configured - data transmitted in plaintext"
                fi
                
                # Logging configuration (CRITICAL FOR AUDITING)
                if grep -q "destination.*file" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB File Logging" "PASS" "File logging enabled"
                else
                    add_test_result "MongoDB File Logging" "FAIL" "File logging not configured"
                fi
                
                if grep -q "verbosity.*2\|verbosity.*3" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Verbose Logging" "PASS" "Verbose logging enabled for security"
                else
                    add_test_result "MongoDB Verbose Logging" "WARN" "Verbose logging not enabled"
                fi
                
                # Security-specific logging
                if grep -q "auditLog:" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Audit Logging" "PASS" "Audit logging configured"
                else
                    add_test_result "MongoDB Audit Logging" "WARN" "Audit logging not configured (Enterprise feature)"
                fi
                
                # Storage engine security
                if grep -q "engine.*wiredTiger" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB Storage Engine" "PASS" "WiredTiger storage engine (recommended)"
                    
                    # Check for encryption at rest
                    if grep -q "encryptionKeyFile\|encryptionCipherMode" "$mongo_conf" 2>/dev/null; then
                        add_test_result "MongoDB Encryption at Rest" "PASS" "Database encryption configured"
                    else
                        add_test_result "MongoDB Encryption at Rest" "WARN" "Database not encrypted at rest"
                    fi
                else
                    add_test_result "MongoDB Storage Engine" "WARN" "Storage engine not explicitly configured"
                fi
                
                # JavaScript execution security
                if grep -q "javascriptEnabled.*false" "$mongo_conf" 2>/dev/null; then
                    add_test_result "MongoDB JavaScript Execution" "PASS" "JavaScript execution disabled"
                else
                    add_test_result "MongoDB JavaScript Execution" "WARN" "JavaScript execution enabled (security risk)"
                fi
            else
                add_test_result "MongoDB Configuration" "FAIL" "Configuration file not found - using dangerous defaults"
            fi
            
            # Process user check (CRITICAL)
            mongo_user=$(ps aux | grep mongod | grep -v grep | grep -v root | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$mongo_user" = "mongodb" ] || [ "$mongo_user" = "mongod" ]; then
                add_test_result "MongoDB Process User" "PASS" "Running as dedicated user: $mongo_user"
            elif [ ! -z "$mongo_user" ] && [ "$mongo_user" != "root" ]; then
                add_test_result "MongoDB Process User" "PASS" "Running as: $mongo_user"
            else
                add_test_result "MongoDB Process User" "FAIL" "Running as root - CRITICAL SECURITY RISK"
            fi
            
            # Port security
            if netstat -tlnp 2>/dev/null | grep -q ":27017.*mongod"; then
                port_binding=$(netstat -tlnp 2>/dev/null | grep ":27017" | awk '{print $4}' | head -1)
                if echo "$port_binding" | grep -q "127.0.0.1:27017"; then
                    add_test_result "MongoDB Port Security" "PASS" "Port 27017 bound to localhost only"
                elif echo "$port_binding" | grep -q "0.0.0.0:27017"; then
                    add_test_result "MongoDB Port Security" "FAIL" "Port 27017 accessible from any IP - CRITICAL RISK"
                else
                    add_test_result "MongoDB Port Security" "PASS" "Port 27017 bound to: $port_binding"
                fi
            elif netstat -tlnp 2>/dev/null | grep mongod | grep -q ":"; then
                mongo_port=$(netstat -tlnp 2>/dev/null | grep mongod | awk '{print $4}' | cut -d: -f2 | head -1)
                add_test_result "MongoDB Custom Port" "PASS" "Running on custom port: $mongo_port"
            fi
            
            # Data directory security
            mongo_datadir="/var/lib/mongodb"
            if [ -d "$mongo_datadir" ]; then
                datadir_perms=$(stat -c "%a" "$mongo_datadir" 2>/dev/null)
                datadir_owner=$(stat -c "%U" "$mongo_datadir" 2>/dev/null)
                
                if [ "$datadir_perms" = "755" ] || [ "$datadir_perms" = "750" ] || [ "$datadir_perms" = "700" ]; then
                    add_test_result "MongoDB Data Directory Perms" "PASS" "Secure permissions ($datadir_perms)"
                else
                    add_test_result "MongoDB Data Directory Perms" "FAIL" "Insecure permissions: $datadir_perms"
                fi
                
                if [ "$datadir_owner" = "mongodb" ] || [ "$datadir_owner" = "mongod" ]; then
                    add_test_result "MongoDB Data Directory Owner" "PASS" "Owned by database user: $datadir_owner"
                else
                    add_test_result "MongoDB Data Directory Owner" "FAIL" "Wrong ownership: $datadir_owner"
                fi
            fi
        else
            add_test_result "MongoDB Service" "WARN" "MongoDB service not running"
        fi
    else
        add_test_result "MongoDB" "INFO" "MongoDB not installed"
    fi
    
    # Redis Security Tests (CRITICAL - Redis defaults are VERY insecure)
    if command -v redis-server >/dev/null 2>&1 || command -v redis-cli >/dev/null 2>&1 || systemctl is-active --quiet redis 2>/dev/null || systemctl is-active --quiet redis-server 2>/dev/null; then
        redis_version=$(redis-server --version 2>/dev/null | awk '{print $1,$2,$3}' || echo "Redis detected")
        add_test_result "Redis Installation" "PASS" "$redis_version"
        
        # Check if Redis is running
        if systemctl is-active --quiet redis 2>/dev/null || systemctl is-active --quiet redis-server 2>/dev/null || pgrep redis-server >/dev/null 2>&1; then
            add_test_result "Redis Service" "PASS" "Redis service is running"
            
            # Redis configuration (CRITICAL - Redis defaults are dangerous!)
            redis_conf="/etc/redis/redis.conf"
            redis_conf_alt="/etc/redis.conf"
            redis_config=""
            
            if [ -f "$redis_conf" ]; then
                redis_config="$redis_conf"
            elif [ -f "$redis_conf_alt" ]; then
                redis_config="$redis_conf_alt"
            fi
            
            if [ ! -z "$redis_config" ]; then
                # Bind address (MOST CRITICAL - Redis default allows external access!)
                if grep -q "^bind 127.0.0.1" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis Bind Address" "PASS" "Bound to localhost only"
                elif grep -q "^bind 0.0.0.0" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis Bind Address" "FAIL" "Bound to all interfaces - CRITICAL RISK"
                else
                    add_test_result "Redis Bind Address" "FAIL" "Bind address not configured - default allows external access"
                fi
                
                # Password authentication (CRITICAL - Redis default has NO PASSWORD!)
                if grep -q "^requirepass" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis Authentication" "PASS" "Password authentication enabled"
                else
                    add_test_result "Redis Authentication" "FAIL" "No password authentication - CRITICAL RISK"
                fi
                
                # Protected mode (Redis 3.2+ security feature)
                if grep -q "^protected-mode yes" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis Protected Mode" "PASS" "Protected mode enabled"
                elif grep -q "^protected-mode no" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis Protected Mode" "FAIL" "Protected mode disabled - security risk"
                else
                    add_test_result "Redis Protected Mode" "WARN" "Protected mode not explicitly configured"
                fi
                
                # Dangerous commands (CRITICAL - Can be exploited for RCE)
                dangerous_cmds="FLUSHDB FLUSHALL CONFIG SHUTDOWN DEBUG EVAL"
                dangerous_found=0
                for cmd in $dangerous_cmds; do
                    if grep -q "^rename-command.*$cmd" "$redis_config" 2>/dev/null; then
                        dangerous_found=1
                    fi
                done
                
                if [ "$dangerous_found" -gt 0 ]; then
                    add_test_result "Redis Dangerous Commands" "PASS" "Dangerous commands renamed/disabled"
                else
                    add_test_result "Redis Dangerous Commands" "FAIL" "Dangerous commands not disabled - RCE risk"
                fi
                
                # SSL/TLS configuration (Redis 6.0+)
                if grep -q "^tls-port\|^tls-cert-file" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis SSL/TLS" "PASS" "SSL/TLS configured"
                else
                    add_test_result "Redis SSL/TLS" "WARN" "SSL/TLS not configured"
                fi
                
                # Logging security
                if grep -q "^logfile" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis Logging" "PASS" "File logging configured"
                else
                    add_test_result "Redis Logging" "WARN" "File logging not configured"
                fi
                
                # ACL security (Redis 6.0+)
                if grep -q "^user\|^aclfile" "$redis_config" 2>/dev/null; then
                    add_test_result "Redis ACL" "PASS" "Access Control Lists configured"
                else
                    add_test_result "Redis ACL" "WARN" "ACL not configured (upgrade to Redis 6.0+ recommended)"
                fi
            else
                add_test_result "Redis Configuration" "FAIL" "Configuration file not found - using dangerous defaults"
            fi
            
            # Process user check (CRITICAL)
            redis_user=$(ps aux | grep redis | grep -v grep | grep -v root | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$redis_user" = "redis" ]; then
                add_test_result "Redis Process User" "PASS" "Running as redis user"
            elif [ ! -z "$redis_user" ] && [ "$redis_user" != "root" ]; then
                add_test_result "Redis Process User" "PASS" "Running as: $redis_user"
            else
                add_test_result "Redis Process User" "FAIL" "Running as root - CRITICAL SECURITY RISK"
            fi
            
            # Port security
            if netstat -tlnp 2>/dev/null | grep -q ":6379.*redis"; then
                port_binding=$(netstat -tlnp 2>/dev/null | grep ":6379" | awk '{print $4}' | head -1)
                if echo "$port_binding" | grep -q "127.0.0.1:6379"; then
                    add_test_result "Redis Port Security" "PASS" "Port 6379 bound to localhost only"
                elif echo "$port_binding" | grep -q "0.0.0.0:6379"; then
                    add_test_result "Redis Port Security" "FAIL" "Port 6379 accessible from any IP - CRITICAL RISK"
                else
                    add_test_result "Redis Port Security" "PASS" "Port 6379 bound to: $port_binding"
                fi
            elif netstat -tlnp 2>/dev/null | grep redis | grep -q ":"; then
                redis_port=$(netstat -tlnp 2>/dev/null | grep redis | awk '{print $4}' | cut -d: -f2 | head -1)
                add_test_result "Redis Custom Port" "PASS" "Running on custom port: $redis_port"
            fi
        else
            add_test_result "Redis Service" "WARN" "Redis service not running"
        fi
    else
        add_test_result "Redis" "INFO" "Redis not installed"
    fi
    
    # General Database Security Checks
    
    # Check for database backup files in common locations
    backup_locations="/var/backups /backup /home/*/backup /opt/backup"
    found_backups=0
    for location in $backup_locations; do
        backup_count=0
        for pattern in "*.sql" "*.dump" "*.bak" "*.gz"; do
            if ls $location/$pattern 2>/dev/null | head -1 | grep -q .; then
                backup_count=$((backup_count + 1))
            fi
        done
        if [ "$backup_count" -gt 0 ]; then
            found_backups=1
            break
        fi
    done
    
    if [ "$found_backups" -eq 1 ]; then
        add_test_result "Database Backup Files" "PASS" "Database backup files found"
    else
        add_test_result "Database Backup Files" "FAIL" "No database backup files found - data loss risk"
    fi
    
    # Check for database-related cron jobs (automated backups)
    if crontab -l 2>/dev/null | grep -q -E "mysqldump|pg_dump|mongodump" || grep -r -E "mysqldump|pg_dump|mongodump" /etc/cron* 2>/dev/null | grep -q .; then
        add_test_result "Database Backup Automation" "PASS" "Automated database backups configured"
    else
        add_test_result "Database Backup Automation" "FAIL" "No automated database backup found - data loss risk"
    fi
    
    # Check for database recovery testing
    recovery_found=0
    for pattern in "/var/backups/*recovery*" "/backup/*recovery*"; do
        if ls $pattern 2>/dev/null | head -1 | grep -q .; then
            recovery_found=1
            break
        fi
    done
    if [ "$recovery_found" -eq 1 ] || crontab -l 2>/dev/null | grep -q recovery; then
        add_test_result "Database Recovery Testing" "PASS" "Recovery testing evidence found"
    else
        add_test_result "Database Recovery Testing" "WARN" "No evidence of recovery testing (verify backup integrity)"
    fi
}

# Mail Server Specialized Tests
test_mail_server_security() {
    show_loading "Analyzing mail server security" 40
    
    # Postfix Security Tests (SMTP Server)
    if command -v postfix >/dev/null 2>&1 || systemctl is-active --quiet postfix 2>/dev/null; then
        if command -v postfix >/dev/null 2>&1; then
            postfix_version=$(postfix version 2>/dev/null || echo "Postfix detected")
            add_test_result "Postfix Installation" "PASS" "$postfix_version"
        fi
        
        if systemctl is-active --quiet postfix 2>/dev/null; then
            add_test_result "Postfix Service" "PASS" "Postfix SMTP server is running"
            
            # Postfix main configuration
            postfix_main="/etc/postfix/main.cf"
            if [ -f "$postfix_main" ]; then
                # SMTP Authentication (CRITICAL - prevents open relay)
                if grep -q "^smtpd_sasl_auth_enable.*yes" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix SMTP AUTH" "PASS" "SMTP authentication enabled"
                else
                    add_test_result "Postfix SMTP AUTH" "FAIL" "SMTP authentication disabled - OPEN RELAY RISK"
                fi
                
                # TLS/SSL Configuration (CRITICAL)
                if grep -q "^smtpd_tls_security_level.*encrypt\|^smtpd_tls_security_level.*may" "$postfix_main" 2>/dev/null; then
                    tls_level=$(grep "^smtpd_tls_security_level" "$postfix_main" | awk '{print $3}')
                    if [ "$tls_level" = "encrypt" ]; then
                        add_test_result "Postfix TLS Security" "PASS" "TLS encryption required"
                    else
                        add_test_result "Postfix TLS Security" "WARN" "TLS optional - encryption not enforced"
                    fi
                else
                    add_test_result "Postfix TLS Security" "FAIL" "TLS not configured - emails sent in plaintext"
                fi
                
                # TLS Certificate Configuration
                if grep -q "^smtpd_tls_cert_file\|^smtpd_tls_key_file" "$postfix_main" 2>/dev/null; then
                    cert_file=$(grep "^smtpd_tls_cert_file" "$postfix_main" | awk '{print $3}' 2>/dev/null)
                    if [ ! -z "$cert_file" ] && [ -f "$cert_file" ]; then
                        add_test_result "Postfix TLS Certificate" "PASS" "TLS certificate configured and exists"
                    else
                        add_test_result "Postfix TLS Certificate" "WARN" "TLS certificate path configured but file not found"
                    fi
                else
                    add_test_result "Postfix TLS Certificate" "FAIL" "No TLS certificate configured"
                fi
                
                # SASL Configuration
                if grep -q "^smtpd_sasl_type.*dovecot\|^smtpd_sasl_path" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix SASL Integration" "PASS" "SASL authentication integration configured"
                else
                    add_test_result "Postfix SASL Integration" "WARN" "SASL integration not configured"
                fi
                
                # Anti-Relay Protection (CRITICAL)
                if grep -q "^smtpd_relay_restrictions\|^smtpd_recipient_restrictions" "$postfix_main" 2>/dev/null; then
                    if grep -q "permit_sasl_authenticated\|reject_unauth_destination" "$postfix_main" 2>/dev/null; then
                        add_test_result "Postfix Relay Protection" "PASS" "Anti-relay restrictions configured"
                    else
                        add_test_result "Postfix Relay Protection" "WARN" "Relay restrictions may be insufficient"
                    fi
                else
                    add_test_result "Postfix Relay Protection" "FAIL" "No relay restrictions - OPEN RELAY RISK"
                fi
                
                # Network binding security
                if grep -q "^inet_interfaces.*localhost\|^inet_interfaces.*127.0.0.1" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix Network Binding" "PASS" "Bound to localhost only"
                elif grep -q "^inet_interfaces.*all" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix Network Binding" "WARN" "Bound to all interfaces - verify security"
                else
                    add_test_result "Postfix Network Binding" "INFO" "Network binding not explicitly configured"
                fi
                
                # Message size limits
                if grep -q "^message_size_limit" "$postfix_main" 2>/dev/null; then
                    size_limit=$(grep "^message_size_limit" "$postfix_main" | awk '{print $3}')
                    add_test_result "Postfix Message Size Limit" "PASS" "Message size limit: $size_limit bytes"
                else
                    add_test_result "Postfix Message Size Limit" "WARN" "No message size limit configured"
                fi
                
                # Rate limiting
                if grep -q "^smtpd_client_connection_rate_limit\|^anvil_rate_time_unit" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix Rate Limiting" "PASS" "Connection rate limiting configured"
                else
                    add_test_result "Postfix Rate Limiting" "WARN" "No rate limiting configured - DoS risk"
                fi
                
                # Hostname validation
                if grep -q "^smtpd_helo_required.*yes" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix HELO Required" "PASS" "HELO command required"
                else
                    add_test_result "Postfix HELO Required" "WARN" "HELO command not required"
                fi
                
                # Virtual domains and users
                if grep -q "^virtual_mailbox_domains\|^virtual_alias_maps" "$postfix_main" 2>/dev/null; then
                    add_test_result "Postfix Virtual Domains" "PASS" "Virtual domains configured"
                else
                    add_test_result "Postfix Virtual Domains" "INFO" "No virtual domains configured"
                fi
            else
                add_test_result "Postfix Configuration" "FAIL" "Main configuration file not found"
            fi
            
            # Postfix master configuration
            postfix_master="/etc/postfix/master.cf"
            if [ -f "$postfix_master" ]; then
                # Check for submission port (587)
                if grep -q "^submission.*inet" "$postfix_master" 2>/dev/null; then
                    add_test_result "Postfix Submission Port" "PASS" "Submission port (587) configured"
                else
                    add_test_result "Postfix Submission Port" "WARN" "Submission port not configured"
                fi
                
                # Check for SMTPS port (465)
                if grep -q "^smtps.*inet" "$postfix_master" 2>/dev/null; then
                    add_test_result "Postfix SMTPS Port" "PASS" "SMTPS port (465) configured"
                else
                    add_test_result "Postfix SMTPS Port" "INFO" "SMTPS port not configured (optional)"
                fi
            fi
            
            # Process user check
            postfix_user=$(ps aux | grep postfix | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$postfix_user" = "postfix" ]; then
                add_test_result "Postfix Process User" "PASS" "Running as postfix user"
            elif [ ! -z "$postfix_user" ] && [ "$postfix_user" != "root" ]; then
                add_test_result "Postfix Process User" "PASS" "Running as: $postfix_user"
            else
                add_test_result "Postfix Process User" "WARN" "Process user needs verification"
            fi
        else
            add_test_result "Postfix Service" "WARN" "Postfix service not running"
        fi
    else
        add_test_result "Postfix" "INFO" "Postfix not installed"
    fi
    
    # Dovecot Security Tests (IMAP/POP3 Server)
    if command -v dovecot >/dev/null 2>&1 || systemctl is-active --quiet dovecot 2>/dev/null; then
        if command -v dovecot >/dev/null 2>&1; then
            dovecot_version=$(dovecot --version 2>/dev/null || echo "Dovecot detected")
            add_test_result "Dovecot Installation" "PASS" "$dovecot_version"
        fi
        
        if systemctl is-active --quiet dovecot 2>/dev/null; then
            add_test_result "Dovecot Service" "PASS" "Dovecot IMAP/POP3 server is running"
            
            # Dovecot main configuration
            dovecot_conf="/etc/dovecot/dovecot.conf"
            dovecot_conf_dir="/etc/dovecot/conf.d"
            
            # SSL/TLS Configuration (CRITICAL)
            if [ -d "$dovecot_conf_dir" ]; then
                # Check SSL settings
                if grep -q "^ssl.*required\|^ssl.*yes" "$dovecot_conf_dir"/* 2>/dev/null; then
                    add_test_result "Dovecot SSL Encryption" "PASS" "SSL encryption required"
                elif grep -q "^ssl.*no" "$dovecot_conf_dir"/* 2>/dev/null; then
                    add_test_result "Dovecot SSL Encryption" "FAIL" "SSL disabled - emails transmitted in plaintext"
                else
                    add_test_result "Dovecot SSL Encryption" "WARN" "SSL configuration not found"
                fi
                
                # SSL Certificate configuration
                if grep -q "^ssl_cert\|^ssl_key" "$dovecot_conf_dir"/* 2>/dev/null; then
                    cert_file=$(grep "^ssl_cert" "$dovecot_conf_dir"/* 2>/dev/null | head -1 | awk '{print $3}' | tr -d '<>')
                    if [ ! -z "$cert_file" ] && [ -f "$cert_file" ]; then
                        add_test_result "Dovecot SSL Certificate" "PASS" "SSL certificate configured and exists"
                    else
                        add_test_result "Dovecot SSL Certificate" "WARN" "SSL certificate configured but file not found"
                    fi
                else
                    add_test_result "Dovecot SSL Certificate" "FAIL" "No SSL certificate configured"
                fi
                
                # SSL protocols and ciphers
                ssl_config_found=0
                if [ -d "$dovecot_conf_dir" ]; then
                    for conf_file in "$dovecot_conf_dir"/*; do
                        if [ -f "$conf_file" ] && grep -q "^ssl_protocols\|^ssl_cipher_list" "$conf_file" 2>/dev/null; then
                            ssl_config_found=1
                            break
                        fi
                    done
                fi
                if [ "$ssl_config_found" -eq 1 ]; then
                    if grep -q "!SSLv2\|!SSLv3" "$dovecot_conf_dir"/* 2>/dev/null; then
                        add_test_result "Dovecot SSL Protocols" "PASS" "Weak SSL protocols disabled"
                    else
                        add_test_result "Dovecot SSL Protocols" "WARN" "SSL protocol security needs review"
                    fi
                else
                    add_test_result "Dovecot SSL Protocols" "WARN" "SSL protocols not explicitly configured"
                fi
                
                # Authentication mechanisms
                if grep -q "^auth_mechanisms" "$dovecot_conf_dir"/* 2>/dev/null; then
                    auth_mechs=$(grep "^auth_mechanisms" "$dovecot_conf_dir"/* 2>/dev/null | awk '{print $3}')
                    if echo "$auth_mechs" | grep -q "plain\|login" && ! echo "$auth_mechs" | grep -q "cram-md5\|digest-md5"; then
                        add_test_result "Dovecot Authentication" "WARN" "Only plaintext authentication configured - use CRAM-MD5"
                    else
                        add_test_result "Dovecot Authentication" "PASS" "Secure authentication mechanisms: $auth_mechs"
                    fi
                else
                    add_test_result "Dovecot Authentication" "WARN" "Authentication mechanisms not explicitly configured"
                fi
                
                # Disable plaintext auth
                if grep -q "^disable_plaintext_auth.*yes" "$dovecot_conf_dir"/* 2>/dev/null; then
                    add_test_result "Dovecot Plaintext Auth" "PASS" "Plaintext authentication disabled"
                elif grep -q "^disable_plaintext_auth.*no" "$dovecot_conf_dir"/* 2>/dev/null; then
                    add_test_result "Dovecot Plaintext Auth" "FAIL" "Plaintext authentication enabled - password theft risk"
                else
                    add_test_result "Dovecot Plaintext Auth" "WARN" "Plaintext authentication setting not found"
                fi
                
                # Login process limits
                if grep -q "^login_max_processes_count\|^login_max_connections" "$dovecot_conf_dir"/* 2>/dev/null; then
                    add_test_result "Dovecot Login Limits" "PASS" "Login process limits configured"
                else
                    add_test_result "Dovecot Login Limits" "WARN" "No login process limits - DoS risk"
                fi
                
                # Mail location security
                if grep -q "^mail_location" "$dovecot_conf_dir"/* 2>/dev/null; then
                    mail_location=$(grep "^mail_location" "$dovecot_conf_dir"/* 2>/dev/null | awk '{print $3}')
                    if echo "$mail_location" | grep -q "maildir:"; then
                        add_test_result "Dovecot Mail Format" "PASS" "Maildir format configured (secure)"
                    else
                        add_test_result "Dovecot Mail Format" "WARN" "Mail format: $mail_location"
                    fi
                else
                    add_test_result "Dovecot Mail Location" "WARN" "Mail location not configured"
                fi
                
                # Logging configuration
                if grep -q "^log_path\|^info_log_path\|^debug_log_path" "$dovecot_conf_dir"/* 2>/dev/null; then
                    add_test_result "Dovecot Logging" "PASS" "Logging configured"
                else
                    add_test_result "Dovecot Logging" "WARN" "Custom logging not configured"
                fi
            elif [ -f "$dovecot_conf" ]; then
                # Fallback to main config file
                if grep -q "ssl.*required\|ssl.*yes" "$dovecot_conf" 2>/dev/null; then
                    add_test_result "Dovecot SSL" "PASS" "SSL encryption configured"
                else
                    add_test_result "Dovecot SSL" "FAIL" "SSL not configured"
                fi
            else
                add_test_result "Dovecot Configuration" "FAIL" "Configuration files not found"
            fi
            
            # Process user check
            dovecot_user=$(ps aux | grep dovecot | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$dovecot_user" = "dovecot" ]; then
                add_test_result "Dovecot Process User" "PASS" "Running as dovecot user"
            elif [ ! -z "$dovecot_user" ] && [ "$dovecot_user" != "root" ]; then
                add_test_result "Dovecot Process User" "PASS" "Running as: $dovecot_user"
            else
                add_test_result "Dovecot Process User" "WARN" "Process user needs verification"
            fi
        else
            add_test_result "Dovecot Service" "WARN" "Dovecot service not running"
        fi
    else
        add_test_result "Dovecot" "INFO" "Dovecot not installed"
    fi
    
    # Exim Security Tests (Alternative SMTP Server)
    if command -v exim4 >/dev/null 2>&1 || systemctl is-active --quiet exim4 2>/dev/null; then
        if command -v exim4 >/dev/null 2>&1; then
            exim_version=$(exim4 -bV 2>/dev/null | head -1 || echo "Exim detected")
            add_test_result "Exim Installation" "PASS" "$exim_version"
        fi
        
        if systemctl is-active --quiet exim4 2>/dev/null; then
            add_test_result "Exim Service" "PASS" "Exim SMTP server is running"
            
            # Check for TLS configuration
            if [ -f "/etc/exim4/exim4.conf.template" ]; then
                if grep -q "tls_certificate\|tls_privatekey" /etc/exim4/exim4.conf.template 2>/dev/null; then
                    add_test_result "Exim TLS Configuration" "PASS" "TLS configuration found"
                else
                    add_test_result "Exim TLS Configuration" "WARN" "TLS not configured"
                fi
            fi
        else
            add_test_result "Exim Service" "WARN" "Exim service not running"
        fi
    else
        add_test_result "Exim" "INFO" "Exim not installed"
    fi
    
    # Mail Security Features and Anti-Spam
    
    # SpamAssassin
    if command -v spamassassin >/dev/null 2>&1 || systemctl is-active --quiet spamassassin 2>/dev/null; then
        add_test_result "SpamAssassin" "PASS" "Anti-spam filtering available"
        
        if systemctl is-active --quiet spamassassin 2>/dev/null; then
            add_test_result "SpamAssassin Service" "PASS" "SpamAssassin service running"
        else
            add_test_result "SpamAssassin Service" "WARN" "SpamAssassin installed but not running"
        fi
    else
        add_test_result "SpamAssassin" "WARN" "No spam filtering detected - spam risk"
    fi
    
    # Amavis (Virus and Spam scanning)
    if command -v amavisd >/dev/null 2>&1 || command -v amavisd-new >/dev/null 2>&1 || systemctl is-active --quiet amavis 2>/dev/null; then
        add_test_result "Amavis" "PASS" "Amavis mail filtering available"
        
        if systemctl is-active --quiet amavis 2>/dev/null; then
            add_test_result "Amavis Service" "PASS" "Amavis service running"
        else
            add_test_result "Amavis Service" "WARN" "Amavis installed but not running"
        fi
    else
        add_test_result "Amavis" "INFO" "Amavis mail filtering not installed"
    fi
    
    # ClamAV (Virus scanning)
    if command -v clamscan >/dev/null 2>&1 || systemctl is-active --quiet clamav-daemon 2>/dev/null; then
        add_test_result "ClamAV" "PASS" "Antivirus scanning available"
        
        if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
            add_test_result "ClamAV Service" "PASS" "ClamAV daemon running"
        else
            add_test_result "ClamAV Service" "WARN" "ClamAV installed but not running"
        fi
    else
        add_test_result "ClamAV" "INFO" "Antivirus scanning not installed"
    fi
    
    # OpenDKIM (DKIM signing)
    if command -v opendkim >/dev/null 2>&1 || systemctl is-active --quiet opendkim 2>/dev/null; then
        add_test_result "OpenDKIM" "PASS" "DKIM signing available"
        
        if systemctl is-active --quiet opendkim 2>/dev/null; then
            add_test_result "OpenDKIM Service" "PASS" "DKIM service running"
        else
            add_test_result "OpenDKIM Service" "WARN" "OpenDKIM installed but not running"
        fi
    else
        add_test_result "OpenDKIM" "WARN" "DKIM signing not configured - email authenticity risk"
    fi
    
    # Check DNS SPF/DMARC records (basic test)
    if command -v dig >/dev/null 2>&1; then
        # Try to get the hostname for SPF checking
        hostname_check=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
        if [ ! -z "$hostname_check" ] && echo "$hostname_check" | grep -q "\\."; then
            # Check for SPF record
            if dig TXT "$hostname_check" +short 2>/dev/null | grep -q "v=spf1"; then
                add_test_result "SPF Record" "PASS" "SPF record found for domain"
            else
                add_test_result "SPF Record" "WARN" "No SPF record found - email spoofing risk"
            fi
            
            # Check for DMARC record
            if dig TXT "_dmarc.$hostname_check" +short 2>/dev/null | grep -q "v=DMARC1"; then
                add_test_result "DMARC Record" "PASS" "DMARC record found for domain"
            else
                add_test_result "DMARC Record" "WARN" "No DMARC record found - email spoofing risk"
            fi
        else
            add_test_result "DNS Email Records" "INFO" "Cannot verify SPF/DMARC (hostname not FQDN)"
        fi
    else
        add_test_result "DNS Email Records" "INFO" "Cannot check SPF/DMARC records (dig not available)"
    fi
    
    # Mail port security checks
    mail_ports="25 587 465 143 993 110 995"
    for port in $mail_ports; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            service_name=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f2 | head -1)
            port_binding=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $4}' | head -1)
            
            case $port in
                25)   protocol="SMTP";;
                587)  protocol="SMTP Submission";;
                465)  protocol="SMTPS";;
                143)  protocol="IMAP";;
                993)  protocol="IMAPS";;
                110)  protocol="POP3";;
                995)  protocol="POP3S";;
            esac
            
            if echo "$port_binding" | grep -q "127.0.0.1:$port"; then
                add_test_result "Mail Port $port ($protocol)" "PASS" "Port $port bound to localhost - $service_name"
            elif echo "$port_binding" | grep -q "0.0.0.0:$port"; then
                add_test_result "Mail Port $port ($protocol)" "PASS" "Port $port open externally - $service_name"
            else
                add_test_result "Mail Port $port ($protocol)" "PASS" "Port $port active - $service_name"
            fi
        fi
    done
    
    # Mail directory permissions
    mail_dirs="/var/mail /var/spool/mail /home/vmail"
    for mail_dir in $mail_dirs; do
        if [ -d "$mail_dir" ]; then
            mail_perms=$(stat -c "%a" "$mail_dir" 2>/dev/null)
            mail_owner=$(stat -c "%U" "$mail_dir" 2>/dev/null)
            
            if [ "$mail_perms" = "755" ] || [ "$mail_perms" = "750" ] || [ "$mail_perms" = "700" ]; then
                add_test_result "Mail Directory Permissions: $(basename $mail_dir)" "PASS" "Secure permissions ($mail_perms) owned by $mail_owner"
            else
                add_test_result "Mail Directory Permissions: $(basename $mail_dir)" "WARN" "Permissions: $mail_perms owned by $mail_owner"
            fi
        fi
    done
    
    # Mail logs check
    mail_logs="/var/log/mail.log /var/log/maillog /var/log/postfix.log"
    mail_log_found=0
    for log_file in $mail_logs; do
        if [ -f "$log_file" ]; then
            add_test_result "Mail Logging" "PASS" "Mail logs found: $(basename $log_file)"
            mail_log_found=1
            break
        fi
    done
    
    if [ "$mail_log_found" -eq 0 ]; then
        add_test_result "Mail Logging" "WARN" "No mail log files found"
    fi
}

# DNS Server Specialized Tests
test_dns_server_security() {
    show_loading "Analyzing DNS server security" 35
    
    # BIND Security Tests (Most popular DNS server)
    if command -v named >/dev/null 2>&1 || command -v bind9 >/dev/null 2>&1 || systemctl is-active --quiet bind9 2>/dev/null || systemctl is-active --quiet named 2>/dev/null; then
        if command -v named >/dev/null 2>&1; then
            bind_version=$(named -v 2>/dev/null | head -1 || echo "BIND detected")
            add_test_result "BIND Installation" "PASS" "$bind_version"
        fi
        
        if systemctl is-active --quiet bind9 2>/dev/null || systemctl is-active --quiet named 2>/dev/null; then
            add_test_result "BIND Service" "PASS" "BIND DNS server is running"
            
            # BIND configuration files
            bind_configs="/etc/bind/named.conf /etc/named.conf"
            bind_options="/etc/bind/named.conf.options /etc/named.conf.options"
            bind_config=""
            bind_options_file=""
            
            for conf in $bind_configs; do
                if [ -f "$conf" ]; then
                    bind_config="$conf"
                    break
                fi
            done
            
            for opts in $bind_options; do
                if [ -f "$opts" ]; then
                    bind_options_file="$opts"
                    break
                fi
            done
            
            if [ ! -z "$bind_config" ]; then
                # Version hiding (CRITICAL - prevents DNS fingerprinting)
                if grep -q "version.*\"none\"\|version.*\"unknown\"" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND Version Hiding" "PASS" "DNS version information hidden"
                else
                    add_test_result "BIND Version Hiding" "FAIL" "DNS version exposed - fingerprinting risk"
                fi
                
                # Hostname hiding
                if grep -q "hostname.*\"none\"\|hostname.*\"unknown\"" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND Hostname Hiding" "PASS" "Server hostname hidden"
                else
                    add_test_result "BIND Hostname Hiding" "WARN" "Server hostname not hidden"
                fi
                
                # Recursion control (CRITICAL - prevents DNS amplification attacks)
                if grep -q "recursion.*no" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND Recursion Control" "PASS" "Recursion disabled (authoritative server)"
                elif grep -q "allow-recursion" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    recursion_acl=$(grep "allow-recursion" "$bind_config" "$bind_options_file" 2>/dev/null | head -1)
                    if echo "$recursion_acl" | grep -q "localhost\|127.0.0.1\|none"; then
                        add_test_result "BIND Recursion Control" "PASS" "Recursion restricted to trusted hosts"
                    else
                        add_test_result "BIND Recursion Control" "WARN" "Recursion allowed - verify ACL configuration"
                    fi
                else
                    add_test_result "BIND Recursion Control" "FAIL" "Recursion not controlled - DNS amplification risk"
                fi
                
                # Query source port randomization
                if grep -q "use-v4-udp-ports\|use-v6-udp-ports" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND Port Randomization" "PASS" "Query source port randomization configured"
                else
                    add_test_result "BIND Port Randomization" "WARN" "Port randomization not explicitly configured"
                fi
                
                # Rate limiting (protects against DoS)
                if grep -q "rate-limit" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND Rate Limiting" "PASS" "DNS rate limiting configured"
                else
                    add_test_result "BIND Rate Limiting" "WARN" "No rate limiting - DoS risk"
                fi
                
                # Zone transfer restrictions (CRITICAL)
                if grep -q "allow-transfer.*none\|allow-transfer.*localhost" "$bind_config" "$bind_options_file" /etc/bind/db.* 2>/dev/null; then
                    add_test_result "BIND Zone Transfer Security" "PASS" "Zone transfers restricted"
                elif grep -q "allow-transfer" "$bind_config" "$bind_options_file" /etc/bind/db.* 2>/dev/null; then
                    add_test_result "BIND Zone Transfer Security" "WARN" "Zone transfer ACL configured - verify restrictions"
                else
                    add_test_result "BIND Zone Transfer Security" "FAIL" "Zone transfers not restricted - information leak risk"
                fi
                
                # Query logging
                if grep -q "querylog.*yes\|logging" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND Query Logging" "PASS" "DNS query logging configured"
                else
                    add_test_result "BIND Query Logging" "WARN" "Query logging not configured"
                fi
                
                # DNSSEC support
                if grep -q "dnssec-enable.*yes\|dnssec-validation.*yes" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    add_test_result "BIND DNSSEC Support" "PASS" "DNSSEC validation enabled"
                else
                    add_test_result "BIND DNSSEC Support" "WARN" "DNSSEC not enabled"
                fi
                
                # Forwarders security
                if grep -q "forwarders" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    forwarders=$(grep "forwarders" "$bind_config" "$bind_options_file" 2>/dev/null | head -1)
                    add_test_result "BIND Forwarders" "PASS" "DNS forwarders configured"
                else
                    add_test_result "BIND Forwarders" "INFO" "No forwarders configured (direct resolution)"
                fi
                
                # Access control lists
                if grep -q "allow-query" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    query_acl=$(grep "allow-query" "$bind_config" "$bind_options_file" 2>/dev/null | head -1)
                    if echo "$query_acl" | grep -q "any"; then
                        add_test_result "BIND Query ACL" "WARN" "Queries allowed from any host"
                    else
                        add_test_result "BIND Query ACL" "PASS" "Query access control configured"
                    fi
                else
                    add_test_result "BIND Query ACL" "WARN" "Query access control not explicitly configured"
                fi
                
                # Directory traversal protection
                if grep -q "directory.*\"/var\|directory.*\"/etc\"" "$bind_config" "$bind_options_file" 2>/dev/null; then
                    bind_dir=$(grep "directory" "$bind_config" "$bind_options_file" 2>/dev/null | awk '{print $2}' | tr -d '";' | head -1)
                    if [ -d "$bind_dir" ]; then
                        dir_perms=$(stat -c "%a" "$bind_dir" 2>/dev/null)
                        if [ "$dir_perms" = "755" ] || [ "$dir_perms" = "750" ]; then
                            add_test_result "BIND Directory Security" "PASS" "BIND directory has secure permissions ($dir_perms)"
                        else
                            add_test_result "BIND Directory Security" "WARN" "BIND directory permissions: $dir_perms"
                        fi
                    fi
                fi
            else
                add_test_result "BIND Configuration" "FAIL" "BIND configuration file not found"
            fi
            
            # Check for zone file security
            zone_dirs="/etc/bind /var/lib/bind /var/named"
            for zone_dir in $zone_dirs; do
                if [ -d "$zone_dir" ]; then
                    zone_files=$(find "$zone_dir" -name "*.zone" -o -name "db.*" 2>/dev/null | wc -l)
                    if [ "$zone_files" -gt 0 ]; then
                        add_test_result "BIND Zone Files" "PASS" "$zone_files zone files found in $zone_dir"
                        
                        # Check zone file permissions
                        insecure_zones=$(find "$zone_dir" -name "*.zone" -o -name "db.*" ! -perm 644 ! -perm 640 2>/dev/null | wc -l)
                        if [ "$insecure_zones" -eq 0 ]; then
                            add_test_result "BIND Zone File Permissions" "PASS" "Zone files have secure permissions"
                        else
                            add_test_result "BIND Zone File Permissions" "WARN" "$insecure_zones zone files with non-standard permissions"
                        fi
                        break
                    fi
                fi
            done
            
            # Process user check (CRITICAL)
            bind_user=$(ps aux | grep -E "named|bind" | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$bind_user" = "bind" ] || [ "$bind_user" = "named" ]; then
                add_test_result "BIND Process User" "PASS" "Running as dedicated user: $bind_user"
            elif [ ! -z "$bind_user" ] && [ "$bind_user" != "root" ]; then
                add_test_result "BIND Process User" "PASS" "Running as: $bind_user"
            else
                add_test_result "BIND Process User" "FAIL" "Running as root - CRITICAL SECURITY RISK"
            fi
        else
            add_test_result "BIND Service" "WARN" "BIND service not running"
        fi
    else
        add_test_result "BIND" "INFO" "BIND not installed"
    fi
    
    # Unbound Security Tests (Modern DNS resolver)
    if command -v unbound >/dev/null 2>&1 || systemctl is-active --quiet unbound 2>/dev/null; then
        if command -v unbound >/dev/null 2>&1; then
            unbound_version=$(unbound -h 2>/dev/null | head -1 || echo "Unbound detected")
            add_test_result "Unbound Installation" "PASS" "$unbound_version"
        fi
        
        if systemctl is-active --quiet unbound 2>/dev/null; then
            add_test_result "Unbound Service" "PASS" "Unbound DNS resolver is running"
            
            # Unbound configuration
            unbound_conf="/etc/unbound/unbound.conf"
            if [ -f "$unbound_conf" ]; then
                # Access control
                if grep -q "access-control:" "$unbound_conf" 2>/dev/null; then
                    if grep -q "access-control:.*refuse\|access-control:.*deny" "$unbound_conf" 2>/dev/null; then
                        add_test_result "Unbound Access Control" "PASS" "Access control configured with restrictions"
                    else
                        add_test_result "Unbound Access Control" "WARN" "Access control configured but may be too permissive"
                    fi
                else
                    add_test_result "Unbound Access Control" "WARN" "No access control configured"
                fi
                
                # Interface binding
                if grep -q "interface:.*127.0.0.1\|interface:.*::1" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound Interface Binding" "PASS" "Bound to localhost only"
                elif grep -q "interface:.*0.0.0.0" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound Interface Binding" "WARN" "Bound to all interfaces - verify security"
                else
                    add_test_result "Unbound Interface Binding" "WARN" "Interface binding not explicitly configured"
                fi
                
                # DNSSEC validation
                if grep -q "auto-trust-anchor-file:\|trust-anchor-file:" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound DNSSEC Validation" "PASS" "DNSSEC validation configured"
                else
                    add_test_result "Unbound DNSSEC Validation" "WARN" "DNSSEC validation not configured"
                fi
                
                # Privacy and security options
                if grep -q "hide-identity:.*yes\|hide-version:.*yes" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound Privacy Settings" "PASS" "Identity and version hiding enabled"
                else
                    add_test_result "Unbound Privacy Settings" "WARN" "Privacy settings not configured"
                fi
                
                # Rate limiting
                if grep -q "ratelimit:\|ip-ratelimit:" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound Rate Limiting" "PASS" "Rate limiting configured"
                else
                    add_test_result "Unbound Rate Limiting" "WARN" "No rate limiting configured"
                fi
                
                # Cache settings
                if grep -q "cache-min-ttl:\|cache-max-ttl:" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound Cache Settings" "PASS" "Cache TTL settings configured"
                else
                    add_test_result "Unbound Cache Settings" "INFO" "Using default cache settings"
                fi
                
                # Logging
                if grep -q "logfile:\|use-syslog:" "$unbound_conf" 2>/dev/null; then
                    add_test_result "Unbound Logging" "PASS" "Logging configured"
                else
                    add_test_result "Unbound Logging" "WARN" "Logging not configured"
                fi
            else
                add_test_result "Unbound Configuration" "WARN" "Unbound configuration file not found"
            fi
            
            # Process user check
            unbound_user=$(ps aux | grep unbound | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$unbound_user" = "unbound" ]; then
                add_test_result "Unbound Process User" "PASS" "Running as unbound user"
            elif [ ! -z "$unbound_user" ] && [ "$unbound_user" != "root" ]; then
                add_test_result "Unbound Process User" "PASS" "Running as: $unbound_user"
            else
                add_test_result "Unbound Process User" "FAIL" "Running as root - CRITICAL SECURITY RISK"
            fi
        else
            add_test_result "Unbound Service" "WARN" "Unbound service not running"
        fi
    else
        add_test_result "Unbound" "INFO" "Unbound not installed"
    fi
    
    # PowerDNS Security Tests
    if command -v pdns_server >/dev/null 2>&1 || systemctl is-active --quiet pdns 2>/dev/null || systemctl is-active --quiet powerdns 2>/dev/null; then
        add_test_result "PowerDNS Installation" "PASS" "PowerDNS detected"
        
        if systemctl is-active --quiet pdns 2>/dev/null || systemctl is-active --quiet powerdns 2>/dev/null; then
            add_test_result "PowerDNS Service" "PASS" "PowerDNS server is running"
            
            # PowerDNS configuration
            pdns_conf="/etc/powerdns/pdns.conf"
            if [ -f "$pdns_conf" ]; then
                # API security
                if grep -q "api=yes\|webserver=yes" "$pdns_conf" 2>/dev/null; then
                    if grep -q "api-key=\|webserver-password=" "$pdns_conf" 2>/dev/null; then
                        add_test_result "PowerDNS API Security" "PASS" "API enabled with authentication"
                    else
                        add_test_result "PowerDNS API Security" "FAIL" "API enabled without authentication - SECURITY RISK"
                    fi
                else
                    add_test_result "PowerDNS API" "INFO" "API not enabled"
                fi
                
                # Database backend security
                if grep -q "launch=.*mysql\|launch=.*pgsql" "$pdns_conf" 2>/dev/null; then
                    add_test_result "PowerDNS Database Backend" "PASS" "Database backend configured"
                else
                    add_test_result "PowerDNS Database Backend" "INFO" "Backend configuration not found"
                fi
            else
                add_test_result "PowerDNS Configuration" "WARN" "PowerDNS configuration not found"
            fi
            
            # Process user check
            pdns_user=$(ps aux | grep pdns | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$pdns_user" = "pdns" ]; then
                add_test_result "PowerDNS Process User" "PASS" "Running as pdns user"
            elif [ ! -z "$pdns_user" ] && [ "$pdns_user" != "root" ]; then
                add_test_result "PowerDNS Process User" "PASS" "Running as: $pdns_user"
            else
                add_test_result "PowerDNS Process User" "WARN" "Process user needs verification"
            fi
        else
            add_test_result "PowerDNS Service" "WARN" "PowerDNS service not running"
        fi
    else
        add_test_result "PowerDNS" "INFO" "PowerDNS not installed"
    fi
    
    # dnsmasq Security Tests (Lightweight DNS forwarder)
    if command -v dnsmasq >/dev/null 2>&1 || systemctl is-active --quiet dnsmasq 2>/dev/null; then
        add_test_result "dnsmasq Installation" "PASS" "dnsmasq detected"
        
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            add_test_result "dnsmasq Service" "PASS" "dnsmasq service is running"
            
            # dnsmasq configuration
            dnsmasq_conf="/etc/dnsmasq.conf"
            if [ -f "$dnsmasq_conf" ]; then
                # Interface binding
                if grep -q "^interface=\|^listen-address=" "$dnsmasq_conf" 2>/dev/null; then
                    add_test_result "dnsmasq Interface Binding" "PASS" "Interface binding configured"
                else
                    add_test_result "dnsmasq Interface Binding" "WARN" "Interface binding not configured"
                fi
                
                # DNSSEC support
                if grep -q "^dnssec" "$dnsmasq_conf" 2>/dev/null; then
                    add_test_result "dnsmasq DNSSEC" "PASS" "DNSSEC support enabled"
                else
                    add_test_result "dnsmasq DNSSEC" "WARN" "DNSSEC support not enabled"
                fi
            else
                add_test_result "dnsmasq Configuration" "WARN" "dnsmasq configuration not found"
            fi
        else
            add_test_result "dnsmasq Service" "WARN" "dnsmasq service not running"
        fi
    else
        add_test_result "dnsmasq" "INFO" "dnsmasq not installed"
    fi
    
    # General DNS Security Checks
    
    # DNS port security
    if netstat -tlnp 2>/dev/null | grep -q ":53 "; then
        dns_process=$(netstat -tlnp 2>/dev/null | grep ":53 " | awk '{print $7}' | cut -d/ -f2 | head -1)
        port_binding=$(netstat -tlnp 2>/dev/null | grep ":53 " | awk '{print $4}' | head -1)
        
        add_test_result "DNS Port 53 (TCP)" "PASS" "DNS service listening: $dns_process"
        
        if echo "$port_binding" | grep -q "127.0.0.1:53"; then
            add_test_result "DNS Port Binding" "PASS" "DNS bound to localhost only"
        elif echo "$port_binding" | grep -q "0.0.0.0:53"; then
            add_test_result "DNS Port Binding" "WARN" "DNS accessible from all interfaces"
        else
            add_test_result "DNS Port Binding" "PASS" "DNS bound to: $port_binding"
        fi
    else
        add_test_result "DNS Port 53" "WARN" "No DNS service detected on port 53"
    fi
    
    # Check UDP port 53 (DNS queries)
    if netstat -ulnp 2>/dev/null | grep -q ":53 "; then
        add_test_result "DNS Port 53 (UDP)" "PASS" "DNS UDP service active"
    else
        add_test_result "DNS Port 53 (UDP)" "WARN" "DNS UDP service not detected"
    fi
    
    # DNS over HTTPS/TLS support
    secure_dns_ports="853 443"
    secure_dns_found=0
    for port in $secure_dns_ports; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port.*dns\|:$port.*doh\|:$port.*dot"; then
            service_name=$(netstat -tlnp 2>/dev/null | grep ":$port" | awk '{print $7}' | cut -d/ -f2 | head -1)
            case $port in
                853) protocol="DNS over TLS (DoT)";;
                443) protocol="DNS over HTTPS (DoH)";;
            esac
            add_test_result "Secure DNS Port $port" "PASS" "$protocol - $service_name"
            secure_dns_found=1
        fi
    done
    
    if [ "$secure_dns_found" -eq 0 ]; then
        add_test_result "Secure DNS Protocols" "INFO" "DNS over HTTPS/TLS not configured"
    fi
    
    # Check for DNS amplification vulnerability (basic test)
    if command -v dig >/dev/null 2>&1; then
        # Test if server allows recursive queries from localhost
        if dig @127.0.0.1 localhost +short >/dev/null 2>&1; then
            add_test_result "DNS Recursion Test" "PASS" "DNS server responding to queries"
        else
            add_test_result "DNS Recursion Test" "INFO" "DNS server not responding (may be authoritative only)"
        fi
    else
        add_test_result "DNS Recursion Test" "INFO" "Cannot test recursion (dig not available)"
    fi
    
    # DNS cache/resolver files security
    dns_cache_dirs="/var/cache/bind /var/cache/unbound /var/lib/unbound"
    for cache_dir in $dns_cache_dirs; do
        if [ -d "$cache_dir" ]; then
            cache_perms=$(stat -c "%a" "$cache_dir" 2>/dev/null)
            cache_owner=$(stat -c "%U" "$cache_dir" 2>/dev/null)
            
            if [ "$cache_perms" = "755" ] || [ "$cache_perms" = "750" ] || [ "$cache_perms" = "700" ]; then
                add_test_result "DNS Cache Directory: $(basename $cache_dir)" "PASS" "Secure permissions ($cache_perms) owned by $cache_owner"
            else
                add_test_result "DNS Cache Directory: $(basename $cache_dir)" "WARN" "Permissions: $cache_perms owned by $cache_owner"
            fi
        fi
    done
    
    # DNS logging
    dns_logs="/var/log/bind /var/log/named.log /var/log/dns.log /var/log/unbound.log"
    dns_log_found=0
    for log_path in $dns_logs; do
        if [ -f "$log_path" ] || [ -d "$log_path" ]; then
            add_test_result "DNS Logging" "PASS" "DNS logs found: $(basename $log_path)"
            dns_log_found=1
            break
        fi
    done
    
    if [ "$dns_log_found" -eq 0 ]; then
        add_test_result "DNS Logging" "WARN" "No DNS log files found"
    fi
    
    # Check for DNS monitoring tools
    dns_monitoring_tools="nslookup dig host"
    for tool in $dns_monitoring_tools; do
        if command -v "$tool" >/dev/null 2>&1; then
            add_test_result "DNS Tool: $tool" "PASS" "DNS diagnostic tool available"
        fi
    done
}

# File Server Specialized Tests
test_file_server_security() {
    show_loading "Analyzing file server security" 45
    
    # Samba/SMB Security Tests (Windows file sharing)
    if command -v smbd >/dev/null 2>&1 || systemctl is-active --quiet smbd 2>/dev/null || systemctl is-active --quiet samba 2>/dev/null; then
        if command -v smbd >/dev/null 2>&1; then
            samba_version=$(smbd --version 2>/dev/null | awk '{print $1,$2}' || echo "Samba detected")
            add_test_result "Samba Installation" "PASS" "$samba_version"
        fi
        
        if systemctl is-active --quiet smbd 2>/dev/null || systemctl is-active --quiet samba 2>/dev/null; then
            add_test_result "Samba Service" "PASS" "Samba SMB server is running"
            
            # Samba configuration analysis
            smb_conf="/etc/samba/smb.conf"
            if [ -f "$smb_conf" ]; then
                # SMB protocol version (CRITICAL - SMB1 is vulnerable)
                if grep -q "min protocol.*SMB2\|min protocol.*SMB3" "$smb_conf" 2>/dev/null; then
                    min_proto=$(grep "min protocol" "$smb_conf" | awk '{print $4}' | head -1)
                    add_test_result "Samba Protocol Version" "PASS" "Minimum protocol: $min_proto (secure)"
                elif grep -q "min protocol.*SMB1\|min protocol.*NT1" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Protocol Version" "FAIL" "SMB1/NT1 allowed - CRITICAL VULNERABILITY"
                else
                    add_test_result "Samba Protocol Version" "WARN" "SMB protocol version not explicitly configured"
                fi
                
                # Max protocol version
                if grep -q "max protocol.*SMB3" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Max Protocol" "PASS" "SMB3 maximum protocol configured"
                else
                    add_test_result "Samba Max Protocol" "WARN" "Maximum protocol not restricted to SMB3"
                fi
                
                # Guest access (CRITICAL - major security risk)
                if grep -q "map to guest.*Never\|map to guest.*Bad User" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Guest Access" "PASS" "Guest access properly restricted"
                elif grep -q "map to guest.*Bad Password" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Guest Access" "WARN" "Guest access on bad password - security risk"
                else
                    add_test_result "Samba Guest Access" "FAIL" "Guest access not properly configured - SECURITY RISK"
                fi
                
                # Server signing (prevents man-in-the-middle attacks)
                if grep -q "server signing.*mandatory\|server signing.*required" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Server Signing" "PASS" "SMB signing required"
                elif grep -q "server signing.*auto\|server signing.*enabled" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Server Signing" "WARN" "SMB signing optional - should be mandatory"
                else
                    add_test_result "Samba Server Signing" "FAIL" "SMB signing not configured - MITM risk"
                fi
                
                # Encryption support (SMB3 feature)
                if grep -q "smb encrypt.*required\|smb encrypt.*mandatory" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Encryption" "PASS" "SMB encryption required"
                elif grep -q "smb encrypt.*desired\|smb encrypt.*auto" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Encryption" "WARN" "SMB encryption optional"
                else
                    add_test_result "Samba Encryption" "WARN" "SMB encryption not configured"
                fi
                
                # Null session restrictions
                if grep -q "restrict anonymous.*2" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Null Sessions" "PASS" "Null sessions blocked"
                else
                    add_test_result "Samba Null Sessions" "WARN" "Null session restrictions not configured"
                fi
                
                # Log level and security logging
                if grep -q "log level.*[2-9]\|log level.*1[0-9]" "$smb_conf" 2>/dev/null; then
                    log_level=$(grep "log level" "$smb_conf" | awk '{print $4}' | head -1)
                    add_test_result "Samba Logging Level" "PASS" "Detailed logging enabled (level $log_level)"
                else
                    add_test_result "Samba Logging Level" "WARN" "Low logging level - security events may be missed"
                fi
                
                # Workgroup/domain security
                if grep -q "security.*user\|security.*domain\|security.*ads" "$smb_conf" 2>/dev/null; then
                    sec_mode=$(grep "security" "$smb_conf" | awk '{print $3}' | head -1)
                    add_test_result "Samba Security Mode" "PASS" "Security mode: $sec_mode"
                else
                    add_test_result "Samba Security Mode" "WARN" "Security mode not explicitly configured"
                fi
                
                # NetBIOS security
                if grep -q "disable netbios.*yes" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba NetBIOS" "PASS" "NetBIOS disabled (recommended)"
                else
                    add_test_result "Samba NetBIOS" "INFO" "NetBIOS not disabled (legacy protocol)"
                fi
                
                # Interface restrictions
                if grep -q "interfaces.*127.0.0.1\|bind interfaces only.*yes" "$smb_conf" 2>/dev/null; then
                    add_test_result "Samba Interface Binding" "PASS" "Network interface restrictions configured"
                else
                    add_test_result "Samba Interface Binding" "WARN" "No interface binding restrictions"
                fi
                
                # Share security analysis
                share_count=$(grep "^\[.*\]" "$smb_conf" 2>/dev/null | grep -v -E "\[global\]|\[homes\]|\[printers\]" | wc -l | tr -d '\n')
                if [ "$share_count" -gt 0 ]; then
                    add_test_result "Samba Shares Detected" "PASS" "$share_count shares configured"
                    
                    # Check for dangerous share options
                    if grep -q "guest ok.*yes\|public.*yes" "$smb_conf" 2>/dev/null; then
                        guest_shares=$(grep -c "guest ok.*yes\|public.*yes" "$smb_conf")
                        add_test_result "Samba Guest Shares" "FAIL" "$guest_shares shares allow guest access - SECURITY RISK"
                    else
                        add_test_result "Samba Guest Shares" "PASS" "No guest-accessible shares found"
                    fi
                    
                    # Check for world-writable shares
                    if grep -q "writable.*yes.*guest\|read only.*no.*guest" "$smb_conf" 2>/dev/null; then
                        add_test_result "Samba Writable Guest Shares" "FAIL" "Writable guest shares detected - CRITICAL RISK"
                    else
                        add_test_result "Samba Share Write Security" "PASS" "No writable guest shares detected"
                    fi
                else
                    add_test_result "Samba Shares" "INFO" "No custom shares configured"
                fi
            else
                add_test_result "Samba Configuration" "FAIL" "Samba configuration file not found"
            fi
            
            # Check Samba process user
            smb_user=$(ps aux | grep smbd | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$smb_user" = "root" ]; then
                add_test_result "Samba Process User" "WARN" "Samba running as root (normal but potential risk)"
            elif [ ! -z "$smb_user" ]; then
                add_test_result "Samba Process User" "PASS" "Samba running as: $smb_user"
            else
                add_test_result "Samba Process User" "WARN" "Cannot determine Samba process user"
            fi
            
            # Check for Samba users
            if command -v pdbedit >/dev/null 2>&1; then
                samba_users=$(pdbedit -L 2>/dev/null | wc -l | tr -d '\n')
                if [ "$samba_users" -gt 0 ]; then
                    add_test_result "Samba User Database" "PASS" "$samba_users Samba users configured"
                else
                    add_test_result "Samba User Database" "WARN" "No Samba users found - authentication may fail"
                fi
            else
                add_test_result "Samba User Tools" "WARN" "Samba user management tools not available"
            fi
        else
            add_test_result "Samba Service" "WARN" "Samba service not running"
        fi
    else
        add_test_result "Samba" "INFO" "Samba not installed"
    fi
    
    # NFS Security Tests (Unix/Linux file sharing)
    if command -v exportfs >/dev/null 2>&1 || systemctl is-active --quiet nfs-server 2>/dev/null || systemctl is-active --quiet nfs-kernel-server 2>/dev/null; then
        add_test_result "NFS Installation" "PASS" "NFS server detected"
        
        if systemctl is-active --quiet nfs-server 2>/dev/null || systemctl is-active --quiet nfs-kernel-server 2>/dev/null; then
            add_test_result "NFS Service" "PASS" "NFS server is running"
            
            # NFS exports security analysis
            if [ -f "/etc/exports" ]; then
                total_exports=$(grep -v "^#\|^$" /etc/exports | wc -l | tr -d '\n')
                if [ "$total_exports" -gt 0 ]; then
                    add_test_result "NFS Exports Found" "PASS" "$total_exports NFS exports configured"
                    
                    # Check for wildcard exports (CRITICAL)
                    wildcard_exports=$(grep -E "\*|0\.0\.0\.0" /etc/exports | grep -v "^#" | wc -l | tr -d '\n')
                    if [ "$wildcard_exports" -gt 0 ]; then
                        add_test_result "NFS Wildcard Exports" "FAIL" "$wildcard_exports exports use wildcards - CRITICAL RISK"
                    else
                        add_test_result "NFS Wildcard Exports" "PASS" "No wildcard exports found"
                    fi
                    
                    # Check for no_root_squash (CRITICAL)
                    no_root_squash=$(grep "no_root_squash" /etc/exports | grep -v "^#" | wc -l | tr -d '\n')
                    if [ "$no_root_squash" -gt 0 ]; then
                        add_test_result "NFS Root Squash" "FAIL" "$no_root_squash exports disable root squashing - CRITICAL RISK"
                    else
                        add_test_result "NFS Root Squash" "PASS" "Root squashing properly configured"
                    fi
                    
                    # Check for read-write exports without restrictions
                    insecure_rw=$(grep -E "rw.*\*|rw.*0\.0\.0\.0" /etc/exports | grep -v "^#" | wc -l | tr -d '\n')
                    if [ "$insecure_rw" -gt 0 ]; then
                        add_test_result "NFS Write Access Security" "FAIL" "$insecure_rw read-write exports without host restrictions"
                    else
                        add_test_result "NFS Write Access Security" "PASS" "Write access properly restricted"
                    fi
                    
                    # Check for sync option (data integrity)
                    async_exports=$(grep "async" /etc/exports | grep -v "^#" | wc -l | tr -d '\n')
                    if [ "$async_exports" -gt 0 ]; then
                        add_test_result "NFS Sync Mode" "WARN" "$async_exports exports use async mode - data integrity risk"
                    else
                        add_test_result "NFS Sync Mode" "PASS" "Exports use sync mode (data integrity)"
                    fi
                    
                    # Check for secure port restriction
                    insecure_ports=$(grep "insecure" /etc/exports | grep -v "^#" | wc -l | tr -d '\n')
                    if [ "$insecure_ports" -gt 0 ]; then
                        add_test_result "NFS Port Security" "WARN" "$insecure_ports exports allow non-privileged ports"
                    else
                        add_test_result "NFS Port Security" "PASS" "Exports restricted to privileged ports"
                    fi
                    
                    # Check for subtree checking
                    no_subtree_check=$(grep "no_subtree_check" /etc/exports | grep -v "^#" | wc -l | tr -d '\n')
                    if [ "$no_subtree_check" -gt 0 ]; then
                        add_test_result "NFS Subtree Checking" "WARN" "$no_subtree_check exports disable subtree checking"
                    else
                        add_test_result "NFS Subtree Checking" "PASS" "Subtree checking enabled (recommended)"
                    fi
                else
                    add_test_result "NFS Exports" "INFO" "No NFS exports configured"
                fi
            else
                add_test_result "NFS Exports File" "WARN" "/etc/exports file not found"
            fi
            
            # NFS version security
            if command -v rpcinfo >/dev/null 2>&1; then
                # Check for NFSv2 (insecure)
                if rpcinfo -p 2>/dev/null | grep -q "nfs.*2"; then
                    add_test_result "NFS Version Security" "FAIL" "NFSv2 enabled - SECURITY RISK (no authentication)"
                elif rpcinfo -p 2>/dev/null | grep -q "nfs.*3"; then
                    add_test_result "NFS Version Security" "WARN" "NFSv3 enabled - consider NFSv4 for better security"
                elif rpcinfo -p 2>/dev/null | grep -q "nfs.*4"; then
                    add_test_result "NFS Version Security" "PASS" "NFSv4 enabled (secure)"
                else
                    add_test_result "NFS Version Security" "INFO" "Cannot determine NFS version"
                fi
            else
                add_test_result "NFS Version Check" "INFO" "rpcinfo not available for version checking"
            fi
            
            # Check NFS process security
            nfs_user=$(ps aux | grep nfsd | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null)
            if [ "$nfs_user" = "root" ]; then
                add_test_result "NFS Process User" "WARN" "NFS running as root (normal but potential risk)"
            elif [ ! -z "$nfs_user" ]; then
                add_test_result "NFS Process User" "PASS" "NFS running as: $nfs_user"
            else
                add_test_result "NFS Process User" "INFO" "Cannot determine NFS process user"
            fi
        else
            add_test_result "NFS Service" "WARN" "NFS service not running"
        fi
    else
        add_test_result "NFS" "INFO" "NFS not installed"
    fi
    
    # FTP Server Security Tests
    if command -v vsftpd >/dev/null 2>&1 || systemctl is-active --quiet vsftpd 2>/dev/null || systemctl is-active --quiet ftp 2>/dev/null; then
        add_test_result "FTP Server" "PASS" "FTP server detected"
        
        if systemctl is-active --quiet vsftpd 2>/dev/null || systemctl is-active --quiet ftp 2>/dev/null; then
            add_test_result "FTP Service" "PASS" "FTP service is running"
            
            # vsftpd configuration security
            vsftpd_conf="/etc/vsftpd.conf"
            if [ -f "$vsftpd_conf" ]; then
                # Anonymous FTP (CRITICAL RISK)
                if grep -q "^anonymous_enable=NO" "$vsftpd_conf" 2>/dev/null; then
                    add_test_result "FTP Anonymous Access" "PASS" "Anonymous FTP disabled"
                elif grep -q "^anonymous_enable=YES" "$vsftpd_conf" 2>/dev/null; then
                    add_test_result "FTP Anonymous Access" "FAIL" "Anonymous FTP enabled - CRITICAL RISK"
                else
                    add_test_result "FTP Anonymous Access" "WARN" "Anonymous FTP setting not explicitly configured"
                fi
                
                # SSL/TLS encryption
                if grep -q "^ssl_enable=YES" "$vsftpd_conf" 2>/dev/null; then
                    add_test_result "FTP SSL/TLS" "PASS" "FTP SSL/TLS encryption enabled"
                else
                    add_test_result "FTP SSL/TLS" "FAIL" "FTP SSL/TLS not enabled - passwords transmitted in plaintext"
                fi
                
                # Local user access
                if grep -q "^local_enable=YES" "$vsftpd_conf" 2>/dev/null; then
                    add_test_result "FTP Local Users" "PASS" "Local user access enabled"
                else
                    add_test_result "FTP Local Users" "INFO" "Local user access disabled"
                fi
                
                # Write access control
                if grep -q "^write_enable=YES" "$vsftpd_conf" 2>/dev/null; then
                    add_test_result "FTP Write Access" "WARN" "FTP write access enabled - verify security"
                else
                    add_test_result "FTP Write Access" "PASS" "FTP write access disabled"
                fi
            else
                add_test_result "FTP Configuration" "WARN" "vsftpd configuration not found"
            fi
        else
            add_test_result "FTP Service" "WARN" "FTP service not running"
        fi
    else
        add_test_result "FTP Server" "INFO" "FTP server not installed"
    fi
    
    # SFTP/SSH File Transfer Security
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
        if grep -q "Subsystem.*sftp" /etc/ssh/sshd_config 2>/dev/null; then
            add_test_result "SFTP Support" "PASS" "SFTP subsystem enabled (secure file transfer)"
            
            # SFTP chroot security
            if grep -q "ChrootDirectory\|ForceCommand.*internal-sftp" /etc/ssh/sshd_config 2>/dev/null; then
                add_test_result "SFTP Chroot Security" "PASS" "SFTP chroot configuration found"
            else
                add_test_result "SFTP Chroot Security" "INFO" "SFTP chroot not configured (optional)"
            fi
        else
            add_test_result "SFTP Support" "INFO" "SFTP subsystem not explicitly configured"
        fi
    fi
    
    # File sharing port security analysis
    file_ports="20 21 139 445 2049 22"
    for port in $file_ports; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            service_name=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f2 | head -1)
            port_binding=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $4}' | head -1)
            
            case $port in
                20|21) protocol="FTP";;
                22)    protocol="SSH/SFTP";;
                139)   protocol="NetBIOS";;
                445)   protocol="SMB/CIFS";;
                2049)  protocol="NFS";;
            esac
            
            if echo "$port_binding" | grep -q "127.0.0.1:$port"; then
                add_test_result "File Sharing Port $port ($protocol)" "PASS" "Port $port bound to localhost - $service_name"
            elif echo "$port_binding" | grep -q "0.0.0.0:$port"; then
                if [ "$port" = "21" ] || [ "$port" = "139" ]; then
                    add_test_result "File Sharing Port $port ($protocol)" "WARN" "Port $port accessible externally - verify security"
                else
                    add_test_result "File Sharing Port $port ($protocol)" "PASS" "Port $port accessible externally - $service_name"
                fi
            else
                add_test_result "File Sharing Port $port ($protocol)" "PASS" "Port $port active - $service_name"
            fi
        fi
    done
    
    # Shared directory security analysis
    common_shares="/srv /var/ftp /home/ftp /var/samba /share /shared"
    for share_dir in $common_shares; do
        if [ -d "$share_dir" ]; then
            share_perms=$(stat -c "%a" "$share_dir" 2>/dev/null)
            share_owner=$(stat -c "%U:%G" "$share_dir" 2>/dev/null)
            
            case "$share_perms" in
                755|750|700) 
                    add_test_result "Share Directory: $(basename $share_dir)" "PASS" "Secure permissions ($share_perms) - $share_owner"
                    ;;
                777|776|666)
                    add_test_result "Share Directory: $(basename $share_dir)" "FAIL" "Insecure permissions ($share_perms) - SECURITY RISK"
                    ;;
                *)
                    add_test_result "Share Directory: $(basename $share_dir)" "WARN" "Permissions ($share_perms) - verify security"
                    ;;
            esac
        fi
    done
    
    # File server logging
    file_logs="/var/log/samba /var/log/smbd.log /var/log/nfsd.log /var/log/vsftpd.log"
    file_log_found=0
    for log_path in $file_logs; do
        if [ -f "$log_path" ] || [ -d "$log_path" ]; then
            add_test_result "File Server Logging" "PASS" "File server logs found: $(basename $log_path)"
            file_log_found=1
            break
        fi
    done
    
    if [ "$file_log_found" -eq 0 ]; then
        add_test_result "File Server Logging" "WARN" "No file server log files found"
    fi
    
    # File system security features
    if command -v mount >/dev/null 2>&1; then
        # Check for file system security options
        if mount | grep -q "noexec\|nosuid\|nodev"; then
            secure_mounts=$(mount | grep -c "noexec\|nosuid\|nodev")
            add_test_result "File System Security Options" "PASS" "$secure_mounts mounts with security options"
        else
            add_test_result "File System Security Options" "WARN" "No security mount options detected"
        fi
    fi
    
    # File access monitoring tools
    monitoring_tools="lsof fuser"
    for tool in $monitoring_tools; do
        if command -v "$tool" >/dev/null 2>&1; then
            add_test_result "File Monitoring Tool: $tool" "PASS" "File access monitoring tool available"
        fi
    done
}



# General Server Specialized Tests
test_general_server_security() {
    show_loading "Analyzing general server security" 18
    
    # Cron Security Tests
    cron_dirs="/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly"
    for cron_dir in $cron_dirs; do
        if [ -d "$cron_dir" ]; then
            cron_perms=$(stat -c "%a" "$cron_dir" 2>/dev/null)
            if [ "$cron_perms" = "755" ] || [ "$cron_perms" = "750" ]; then
                add_test_result "Cron Directory: $(basename $cron_dir)" "PASS" "Secure permissions ($cron_perms)"
            else
                add_test_result "Cron Directory: $(basename $cron_dir)" "WARN" "Permissions: $cron_perms"
            fi
        fi
    done
    
    # System crontab security
    if [ -f "/etc/crontab" ]; then
        crontab_perms=$(stat -c "%a" /etc/crontab 2>/dev/null)
        if [ "$crontab_perms" = "644" ]; then
            add_test_result "System Crontab Permissions" "PASS" "Secure permissions (644)"
        else
            add_test_result "System Crontab Permissions" "WARN" "Permissions: $crontab_perms"
        fi
    fi
    
    # Sudo Configuration Security
    if [ -f "/etc/sudoers" ]; then
        sudoers_perms=$(stat -c "%a" /etc/sudoers 2>/dev/null)
        if [ "$sudoers_perms" = "440" ]; then
            add_test_result "Sudoers File Permissions" "PASS" "Secure permissions (440)"
        else
            add_test_result "Sudoers File Permissions" "WARN" "Permissions: $sudoers_perms"
        fi
        
        # Check for NOPASSWD entries
        nopasswd_entries=0
        nopasswd_entries=$((nopasswd_entries + $(grep -c "NOPASSWD" /etc/sudoers 2>/dev/null || echo "0")))
        if [ -d "/etc/sudoers.d" ]; then
            for sudoers_file in /etc/sudoers.d/*; do
                if [ -f "$sudoers_file" ]; then
                    nopasswd_entries=$((nopasswd_entries + $(grep -c "NOPASSWD" "$sudoers_file" 2>/dev/null || echo "0")))
                fi
            done
        fi
        if [ "$nopasswd_entries" -eq 0 ]; then
            add_test_result "Sudo NOPASSWD Entries" "PASS" "No passwordless sudo entries found"
        else
            add_test_result "Sudo NOPASSWD Entries" "WARN" "$nopasswd_entries passwordless sudo entries found"
        fi
        
        # Check for ALL=(ALL:ALL) ALL entries
        dangerous_sudo=0
        dangerous_sudo=$((dangerous_sudo + $(grep -c "ALL=(ALL:ALL) ALL" /etc/sudoers 2>/dev/null || echo "0")))
        if [ -d "/etc/sudoers.d" ]; then
            for sudoers_file in /etc/sudoers.d/*; do
                if [ -f "$sudoers_file" ]; then
                    dangerous_sudo=$((dangerous_sudo + $(grep -c "ALL=(ALL:ALL) ALL" "$sudoers_file" 2>/dev/null || echo "0")))
                fi
            done
        fi
        if [ "$dangerous_sudo" -le 1 ]; then
            add_test_result "Dangerous Sudo Rules" "PASS" "Limited dangerous sudo rules"
        else
            add_test_result "Dangerous Sudo Rules" "WARN" "$dangerous_sudo dangerous sudo rules found"
        fi
    fi
    
    # System Resource Limits
    if [ -f "/etc/security/limits.conf" ]; then
        add_test_result "Security Limits Config" "PASS" "Resource limits configuration exists"
        
        # Check for core dump restrictions
        if grep -q "^\*.*core.*0" /etc/security/limits.conf 2>/dev/null; then
            add_test_result "Core Dump Restrictions" "PASS" "Core dumps disabled"
        else
            add_test_result "Core Dump Restrictions" "WARN" "Core dumps not restricted"
        fi
    fi
    
    # System Control Parameters (sysctl)
    if [ -f "/etc/sysctl.conf" ]; then
        # IP forwarding
        if grep -q "^net.ipv4.ip_forward.*0" /etc/sysctl.conf 2>/dev/null; then
            add_test_result "IP Forwarding" "PASS" "IP forwarding disabled"
        else
            current_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
            if [ "$current_forward" = "0" ]; then
                add_test_result "IP Forwarding" "PASS" "IP forwarding disabled (runtime)"
            else
                add_test_result "IP Forwarding" "WARN" "IP forwarding enabled"
            fi
        fi
        
        # ICMP redirects
        if grep -q "^net.ipv4.conf.all.accept_redirects.*0" /etc/sysctl.conf 2>/dev/null; then
            add_test_result "ICMP Redirects" "PASS" "ICMP redirects disabled"
        else
            add_test_result "ICMP Redirects" "WARN" "ICMP redirects not explicitly disabled"
        fi
        
        # Source routing
        if grep -q "^net.ipv4.conf.all.accept_source_route.*0" /etc/sysctl.conf 2>/dev/null; then
            add_test_result "Source Routing" "PASS" "Source routing disabled"
        else
            add_test_result "Source Routing" "WARN" "Source routing not explicitly disabled"
        fi
    fi
    
    # Password Policy (PAM)
    if [ -f "/etc/pam.d/common-password" ]; then
        # Check for password complexity
        if grep -q "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null; then
            add_test_result "Password Quality Module" "PASS" "Password quality checking enabled"
        elif grep -q "pam_cracklib.so" /etc/pam.d/common-password 2>/dev/null; then
            add_test_result "Password Quality Module" "PASS" "Password checking enabled (cracklib)"
        else
            add_test_result "Password Quality Module" "WARN" "No password quality checking found"
        fi
        
        # Check for password history
        if grep -q "remember=" /etc/pam.d/common-password 2>/dev/null; then
            add_test_result "Password History" "PASS" "Password history enforcement enabled"
        else
            add_test_result "Password History" "WARN" "Password history not enforced"
        fi
    fi
    
    # Login Security
    if [ -f "/etc/login.defs" ]; then
        # Password aging
        max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        if [ ! -z "$max_days" ] && [ "$max_days" -le 90 ]; then
            add_test_result "Password Max Age" "PASS" "Password expires in $max_days days"
        else
            add_test_result "Password Max Age" "WARN" "Password max age: $max_days days"
        fi
        
        # Password minimum age
        min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        if [ ! -z "$min_days" ] && [ "$min_days" -ge 1 ]; then
            add_test_result "Password Min Age" "PASS" "Password minimum age: $min_days days"
        else
            add_test_result "Password Min Age" "WARN" "Password minimum age not set"
        fi
    fi
    
    # Check for automatic updates
    if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        add_test_result "Automatic Updates" "PASS" "Unattended upgrades enabled"
    elif command -v apt-config >/dev/null 2>&1; then
        if apt-config dump APT::Periodic::Update-Package-Lists 2>/dev/null | grep -q "1"; then
            add_test_result "Automatic Updates" "PASS" "Automatic package list updates enabled"
        else
            add_test_result "Automatic Updates" "WARN" "Automatic updates not configured"
        fi
    else
        add_test_result "Automatic Updates" "WARN" "Cannot determine automatic update status"
    fi
    
    # Backup Services
    backup_tools="rsync bacula amanda duplicity"
    backup_found=0
    for tool in $backup_tools; do
        if command -v "$tool" >/dev/null 2>&1; then
            add_test_result "Backup Tool: $tool" "PASS" "$tool is installed"
            backup_found=1
        fi
    done
    
    if [ "$backup_found" -eq 0 ]; then
        add_test_result "Backup Tools" "WARN" "No common backup tools found"
    fi
    
    # System Monitoring
    monitoring_tools="htop iotop nethogs"
    for tool in $monitoring_tools; do
        if command -v "$tool" >/dev/null 2>&1; then
            add_test_result "Monitoring Tool: $tool" "PASS" "$tool is available"
        fi
    done
}

# Main specialized test coordinator
run_specialized_tests() {
    case "$SERVER_TYPE" in
        "web")
            test_web_server_security
            ;;
        "database")
            test_database_security
            ;;
        "mail")
            test_mail_server_security
            ;;
        "dns")
            test_dns_server_security
            ;;
        "file")
            test_file_server_security
            ;;
        "general")
            test_general_server_security
            ;;
    esac
}

# Show detailed results
show_detailed_results() {
    echo ""
    printf "\033[1;37m╔══════════════════════════════════════════════════════════════════╗\033[0m\n"
    printf "\033[1;37m║\033[1;36m                        DETAILED TEST RESULTS                     \033[1;37m║\033[0m\n"
    printf "\033[1;37m╚══════════════════════════════════════════════════════════════════╝\033[0m\n"
    echo ""
    
    # Collect results by category using grep
    pass_results=$(echo "$TEST_RESULTS" | grep "^$CHECK_MARK" || true)
    fail_results=$(echo "$TEST_RESULTS" | grep "^$CROSS_MARK" || true)
    warn_results=$(echo "$TEST_RESULTS" | grep "^$WARNING_MARK" || true)
    info_results=$(echo "$TEST_RESULTS" | grep "^ⓘ" || true)
    
    # Show PASSED tests
    if [ ! -z "$pass_results" ]; then
        printf "\033[1;32m▶ PASSED TESTS\033[0m\n"
        echo "────────────────────────────────────────────────────────────────────"
        echo "$pass_results" | while IFS= read -r line; do
            if [ ! -z "$line" ]; then
                printf "  \033[1;32m%s\033[0m\n" "$line"
            fi
        done
        echo ""
    fi
    
    # Show FAILED tests
    if [ ! -z "$fail_results" ]; then
        printf "\033[1;31m▶ FAILED TESTS\033[0m\n"
        echo "────────────────────────────────────────────────────────────────────"
        echo "$fail_results" | while IFS= read -r line; do
            if [ ! -z "$line" ]; then
                printf "  \033[0;31m%s\033[0m\n" "$line"
            fi
        done
        echo ""
    fi
    
    # Show WARNING tests
    if [ ! -z "$warn_results" ]; then
        printf "\033[1;33m▶ WARNING TESTS\033[0m\n"
        echo "────────────────────────────────────────────────────────────────────"
        echo "$warn_results" | while IFS= read -r line; do
            if [ ! -z "$line" ]; then
                printf "  \033[1;33m%s\033[0m\n" "$line"
            fi
        done
        echo ""
    fi
    
    # Show INFO tests
    if [ ! -z "$info_results" ]; then
        printf "\033[1;36m▶ INFORMATIONAL ITEMS\033[0m\n"
        echo "────────────────────────────────────────────────────────────────────"
        echo "$info_results" | while IFS= read -r line; do
            if [ ! -z "$line" ]; then
                printf "  \033[1;36m%s\033[0m\n" "$line"
            fi
        done
        echo ""
    fi
}

# Main execution
main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Warning: This script should be run as root for complete testing."
        echo "Some tests may not work properly without root privileges."
        echo ""
        read -p "Continue anyway? (y/N): " choice
        case "$choice" in
            y|Y ) ;;
            * ) echo "Exiting..."; exit 1;;
        esac
    fi
    
    select_server_type
    print_banner
    init_report
    
    # ===== UNIVERSAL TESTS (Run for ALL server types) =====
    printf "\033[1;36m╔══════════════════════════════════════════════════════════════════╗\033[0m\n"
    printf "\033[1;36m║\033[1;37m                      UNIVERSAL SECURITY TESTS                    \033[1;36m║\033[0m\n"
    printf "\033[1;36m║\033[0;33m                    (Applied to ALL server types)                 \033[1;36m║\033[0m\n"
    printf "\033[1;36m╚══════════════════════════════════════════════════════════════════╝\033[0m\n"
    echo ""
    
    test_system_info
    test_user_authentication
    test_ssh_security
    test_firewall
    test_network_security
    test_filesystem_security
    test_package_security
    test_security_tools
    test_kernel_security
    test_mount_security
    test_logging_audit
    test_time_sync
    test_system_services
    test_process_security
    
    # Additional Universal Security Tests
    test_ssl_security
    test_disk_encryption
    test_disk_space_security
    test_open_ports_analysis
    test_dns_configuration
    test_security_updates
    test_package_verification
    test_failed_login_attempts
    test_file_integrity_monitoring
    test_environment_variables
    test_temporary_files_security
    
    # ===== SPECIALIZED TESTS (Run based on server type) =====
    # Only show specialized tests if not general server
    if [ "$SERVER_TYPE" != "general" ]; then
        echo ""
        printf "\033[1;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n"
        printf "\033[1;35m║\033[1;37m                     SPECIALIZED SECURITY TESTS                   \033[1;35m║\033[0m\n"
        printf "\033[1;35m║\033[0;33m                Specific tests for your selected type             \033[1;35m║\033[0m\n"
        printf "\033[1;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n"
        echo ""
        
        run_specialized_tests
    else
        echo ""
        printf "\033[0;36m⚙️  General server selected - All security tests are universal.\033[0m\n"
        echo ""
    fi
    
    # Show detailed results
    show_detailed_results
    
    # Generate final summary
    echo ""
    printf "\033[1;32m✓ Security assessment completed!\033[0m\n"
    printf "\033[0;36mReport saved to: \033[1;37m$REPORT_FILE\033[0m\n"
    echo ""
    printf "\033[0;35m╔══════════════════════════════════════════════════════════════════╗\033[0m\n"
    printf "\033[0;35m║\033[1;37m                      SECURITY SUMMARY                            \033[0;35m║\033[0m\n"
    printf "\033[0;35m╚══════════════════════════════════════════════════════════════════╝\033[0m\n"
    
    # Calculate INFO count
    info_tests=$(echo "$TEST_RESULTS" | grep -c "^ⓘ" || echo "0")
    
    printf "\033[1;37mTotal Tests:\033[0m \033[1;34m%d\033[0m\n" "$TOTAL_TESTS"
    printf "\033[1;37mPassed:\033[0m \033[0;32m%d\033[0m\n" "$PASSED_TESTS"
    printf "\033[1;37mFailed:\033[0m \033[0;31m%d\033[0m\n" "$FAILED_TESTS"
    printf "\033[1;37mWarnings:\033[0m \033[1;33m%d\033[0m\n" "$WARNING_TESTS"
    printf "\033[1;37mInfo:\033[0m \033[1;36m%d\033[0m\n" "$info_tests"
    
    if [ $TOTAL_TESTS -gt 0 ]; then
        security_score=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
        printf "\033[1;37mSecurity Score:\033[0m \033[1;36m%d%%\033[0m\n" "$security_score"
    fi
    
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ] && [ $WARNING_TESTS -lt 10 ]; then
        printf "\033[0;32m🎉 Excellent! Your %s server has a strong security posture.\033[0m\n" "$SERVER_TYPE"
    elif [ $FAILED_TESTS -lt 3 ] && [ $WARNING_TESTS -lt 20 ]; then
        printf "\033[1;33m👍 Good security posture with room for improvement.\033[0m\n"
    else
        printf "\033[0;31m⚠️  Security posture needs attention. Review failed tests.\033[0m\n"
    fi
    
    echo ""
}

# Check for help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Server Security Check"
    echo "Usage: $0"
    echo ""
    echo "This script performs comprehensive security testing on Ubuntu systems."
    echo "It is recommended to run this script as root for complete testing."
    exit 0
fi

# Run main function
main "$@" 