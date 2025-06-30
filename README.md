# 🛡️ Server Security Analysis Tool

A helpful security testing tool for Ubuntu/Linux servers that checks your system's security configuration with a friendly interface and clear reporting.

## ⭐ **Quick Start**

#### **🚀 One-Line Installation & Execution & Run:**
```bash
wget -O security_check.sh https://raw.githubusercontent.com/enesutku/server-security-check/main/server-security-check.sh && chmod +x security_check.sh && sudo ./security_check.sh
```

#### **📥 Download, Make Executable:**
```bash
wget -O security_check.sh https://raw.githubusercontent.com/enesutku/server-security-check/main/server-security-check.sh && chmod +x security_check.sh
```

#### **🔧 Manual Installation:**
```bash
# Download the script
wget https://raw.githubusercontent.com/enesutku/server-security-check/main/server-security-check.sh

# Make it executable
chmod +x server-security-check.sh

# Run the security analysis
sudo ./server-security-check.sh
```

## 🎯 **What Does This Tool Do?**

This tool helps you check your Linux server's security by running 150+ different tests. It's designed to help:

- **Anyone** curious about their server's security status
- **System Administrators** who want to check their servers
- **DevOps Teams** learning about security best practices  

## ✨ **What You Get**

- 🔍 **150+ Security Checks** - Covers the most important security areas
- 🎨 **Friendly Interface** - Easy-to-read colored results with simple animations  
- 📊 **Clear Reports** - Saves detailed findings to a text file you can review
- 🏷️ **Smart Testing** - Adapts tests based on what type of server you have
- 🔒 **Safe Operation** - Only reads your system, doesn't change anything
- 📈 **Simple Scoring** - Shows your security level as a percentage

## 🖥️ **Server Types We Support**

The tool asks what kind of server you have and runs extra tests accordingly:

1. **General Server** - Standard server with no specific role
2. **Web Server** - Apache, Nginx, HTTP/HTTPS services
3. **Database Server** - MySQL, PostgreSQL, MariaDB, MongoDB, Redis
4. **Mail Server** - Postfix, Dovecot, SMTP/IMAP services
5. **DNS Server** - BIND, Unbound, DNS services  
6. **File Server** - Samba, NFS, FTP, file sharing services

## 🔬 **Security Tests Overview**

### **Universal Tests (Applied to ALL servers)**

#### **🔐 Authentication & User Security**
- Root UID uniqueness verification
- Empty password detection
- Password aging policy analysis
- Shell access user enumeration
- Account lockout detection
- Failed login attempt analysis

#### **🌐 Network Security**
- SSH configuration hardening
- Firewall status and rules (UFW/iptables)
- Open port analysis and service identification
- IP forwarding and ICMP redirect checks
- Insecure service detection (telnet, FTP, RSH)
- Network interface security

#### **📁 File System Security**
- Critical file permissions (/etc/passwd, /etc/shadow)
- World-writable file detection
- SUID/SGID file analysis
- Temporary directory security (/tmp, /var/tmp)
- Mount security options (noexec, nosuid, nodev)
- Sensitive file exposure checks

#### **📦 Package Management Security**
- System update availability
- Security update priority analysis
- Package integrity verification
- Automatic update configuration
- Third-party repository security
- Package signing key validation

#### **🔧 Kernel & System Security**
- ASLR (Address Space Layout Randomization)
- DEP/NX bit support verification
- Kernel module loading restrictions
- Kernel pointer restriction analysis
- System information gathering
- Process security analysis

#### **📋 Logging & Monitoring**
- Authentication log analysis
- System log configuration
- Failed login pattern detection
- Brute force attempt identification
- Suspicious IP pattern analysis
- Account lockout detection and analysis
- File integrity monitoring setup
- Security event tracking
- Fail2ban integration and status

#### **🔒 Advanced Security Features**
- SSL certificate analysis
- Disk encryption detection
- Environment variable security
- File access monitoring tools
- Security tool installation (fail2ban)
- Time synchronization security

#### **⚙️ System Services & Process Security**
- Critical system service analysis
- Service startup configuration
- Process privilege verification
- Service account security
- Daemon security assessment
- System service monitoring
- AppArmor security profile analysis
- Process isolation and sandboxing
- Service user privilege restrictions

#### **💾 Storage & Space Security**
- Disk space utilization monitoring
- Critical filesystem space alerts
- Storage quota enforcement
- Temporary file cleanup verification
- Log rotation and space management

#### **🔍 Network Analysis & Monitoring**
- Open port comprehensive analysis
- Service identification and mapping
- Network interface security assessment
- DNS configuration validation
- Resolver security verification
- Network binding analysis

#### **📋 Compliance & Verification**
- Security update availability checking
- Package signature verification
- System integrity validation
- Configuration compliance testing
- Security baseline assessment

### **Specialized Tests (Server Type Specific)**

#### **🌐 Web Server Security**
**Apache Security:**
- Protocol version enforcement (SMB2/3 vs SMB1)
- Server token and signature hiding
- Directory indexing protection
- ModSecurity WAF detection
- Dangerous module identification
- SSL/TLS configuration analysis

**Nginx Security:**
- Server token hiding
- User privilege verification
- Directory indexing controls
- SSL configuration validation

**Web Application Security:**
- PHP configuration hardening
- Node.js process security
- HTTP security headers analysis
- Sensitive file detection in web root
- Backup file exposure checks
- Database integration security

#### **📧 Mail Server Security**
**Postfix Security:**
- SMTP authentication configuration
- TLS/SSL encryption enforcement
- Anti-relay protection (critical open relay prevention)
- SASL integration verification
- Network binding security analysis
- Message size and rate limiting
- HELO command requirements
- Virtual domain configuration

**Dovecot Security:**
- SSL/TLS encryption requirements
- Authentication mechanism security
- Plaintext authentication controls
- Login process limits and DoS protection
- Mail storage format security (Maildir)
- Certificate configuration validation
- Process privilege verification

**Exim Security:**
- Alternative SMTP server security analysis
- TLS configuration validation
- Mail routing security
- Process user verification

**Anti-Spam and Security Tools:**
- SpamAssassin integration testing
- Amavis virus/spam filtering
- ClamAV antivirus scanning
- OpenDKIM signature validation
- SPF record verification
- DMARC policy checking

**Mail Protocol Security:**
- SMTP, SMTPS, IMAP, IMAPS port analysis
- POP3, POP3S security assessment
- Mail directory permission validation
- Logging configuration verification

#### **🗄️ Database Server Security**
**MySQL/MariaDB Security:**
- Network binding restrictions
- SSL/TLS encryption enforcement
- Authentication configuration
- Binary and error logging
- Root squashing verification
- Data directory permissions
- Dangerous function restrictions

**PostgreSQL Security:**
- Connection authentication (trust vs encrypted)
- SSL certificate validation
- Statement and connection logging
- HBA configuration analysis
- Process user verification

**MongoDB Security:**
- Authentication requirement enforcement
- Network binding security
- SSL/TLS configuration
- JavaScript execution restrictions
- Audit logging configuration

**Redis Security:**
- Password authentication verification
- Network interface restrictions
- Dangerous command protection
- Protected mode validation
- ACL configuration analysis

**Database Backup & Recovery:**
- Database backup file detection
- Automated backup verification
- Recovery testing evidence
- Backup security and encryption
- Database recovery system readiness

#### **🌍 DNS Server Security**
**BIND Security:**
- Version information hiding
- DNS amplification protection
- Zone transfer restrictions
- Query logging configuration
- DNSSEC validation setup
- Rate limiting implementation

**Unbound Security:**
- Access control configuration
- Interface binding restrictions
- DNSSEC validation
- Privacy settings enforcement

**General DNS Security:**
- Recursive query controls
- Port randomization
- Cache poisoning protection
- Secure DNS protocol support (DoT/DoH)

#### **📂 File Server Security**
**Samba/SMB Security:**
- SMB1 protocol vulnerability detection
- Guest access restrictions
- Server signing enforcement
- Share permission analysis
- Encryption requirements
- User database verification

**NFS Security:**
- Export wildcard detection
- Root squashing enforcement
- Version security analysis (NFSv2 vs NFSv4)
- Write access restrictions
- Sync mode validation

**FTP Security:**
- Anonymous access prevention
- SSL/TLS encryption enforcement
- User authentication validation
- Directory access controls

**File Access Monitoring:**
- File access monitoring tools (lsof, fuser)
- Share directory permission analysis
- File system security mount options
- SFTP chroot security configuration
- File sharing port security analysis

#### **⚙️ General Server Security**
**System Administration Security:**
- Cron job security and directory permissions
- Sudoers file permissions and dangerous rules
- NOPASSWD sudo entries detection
- System resource limits configuration
- Core dump restrictions

**System Hardening Parameters:**
- IP forwarding controls (sysctl)
- ICMP redirect prevention
- Source routing protection
- Network parameter security
- Kernel security parameters

**Authentication & Password Policy:**
- PAM (Pluggable Authentication Modules) configuration
- Password quality enforcement (pam_pwquality/cracklib)
- Password history enforcement
- Login security policies (/etc/login.defs)
- Password aging and complexity requirements

**Backup & Recovery:**
- Backup tool availability (rsync, bacula, amanda, duplicity)
- Automated backup verification
- Recovery system readiness
- Backup file security analysis

**System Monitoring & Maintenance:**
- System monitoring tools (htop, iotop, nethogs)
- Automatic update configuration
- System maintenance scheduling
- Performance monitoring capabilities

## 📋 **How It Works**

1. **Choose Your Server Type** - Pick from 6 different server types
2. **Watch the Tests Run** - See 150+ checks with friendly loading animations
3. **Review Your Results** - Get easy-to-understand color-coded results
4. **Check the Report** - Find detailed results saved to `/tmp/ubuntu_security_report.txt`

## 💡 **Prerequisites**

- Ubuntu/Debian Linux system (or most other Linux distributions)
- Root or sudo privileges (recommended for complete testing)
- Basic system utilities (usually already installed)

## 📊 **Understanding Your Results**

### **What the Colors Mean**
- ✅ **PASS** - This security setting looks good
- ❌ **FAIL** - This needs your attention (potential security issue)
- ⚠️ **WARN** - This could be improved for better security
- ℹ️ **INFO** - Just letting you know about this setting

### **Your Security Score**
- **90-100%** - Great job! Your server looks very secure
- **70-89%** - Pretty good, just a few things to improve
- **50-69%** - Okay, but there's room for improvement
- **Below 50%** - Might want to look into some security improvements

## ⚠️ **Good to Know**

### **Keep in Mind**
- You'll get better results if you run it with sudo/root
- These results are a starting point - consider getting professional advice for critical systems
- This tool checks configuration files, not real-time system behavior
- For high-security environments, you might want additional professional testing

## 📈 **What You'll Learn**

The tool helps you understand:

- **Things to Fix** - Issues that need attention
- **Security Tips** - Ways to make your server more secure
- **Best Practices** - Common security recommendations
- **Next Steps** - Ideas for ongoing security maintenance

## 📝 **Your Report**

You'll get a detailed report with:
- A summary of your security score
- List of findings organized by category
- Suggestions for improvements
- Technical details about your system
- Reference information for security standards

## 🤝 **Want to Help?**

This tool is open for improvements! You can help by:
- Adding new security checks
- Supporting more server types
- Making the reports even better
- Improving the documentation

## 📄 **License & Usage**

This tool is free to use for learning and checking your own systems. Just make sure you:
- Only run it on systems you own or have permission to test
- Follow your local laws and company policies
- Use the results responsibly

---

**⚠️ Please Note:** Only use this tool on servers you own or have explicit permission to test. Be responsible with security testing!

**🚨 Disclaimer:** You are fully responsible for running this script and any consequences that may result. We accept no liability for any damage, data loss, system issues, or other problems that may occur from using this tool. Use at your own risk and always test on non-production systems first when possible. 
