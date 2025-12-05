# Changelog

All notable changes to the Dolutech Security Automate System (DSAS) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2025-12-05

### ✨ Added

#### Security Enhancements
- **Input Validation Functions**
  - `validate_port()` - Validates port numbers (1-65535)
  - `validate_ipv4()` - Validates IPv4 addresses with proper octet checking
  - `validate_ipv6()` - Validates IPv6 addresses
  - `validate_hostname()` - Validates hostnames according to RFC standards
  - `validate_path()` - Prevents command injection in file paths

- **Enhanced Logging System**
  - `log_error()` - Timestamped error logging
  - `log_info()` - Timestamped info logging
  - `log_success()` - Timestamped success logging
  - `check_command()` - Automatic error checking for commands

- **Firewall Improvements**
  - Automatic iptables rules persistence
  - `save_iptables_rules()` function with distribution detection
  - Automatic installation of iptables-persistent on Debian/Ubuntu
  - Visual firewall rules viewer (option 7 in firewall menu)
  - Manual save option (option 8 in firewall menu)
  - Warning system for blocking critical ports (SSH)

- **Password Security**
  - Minimum password length validation (8 characters)
  - Secure password handling using stdin pipes
  - Automatic password cleanup from memory with `unset`
  - No password exposure in process lists

- **Missing Functions Implementation**
  - `view_logs()` - Display last 50 lines of DSAS logs
  - `clear_logs()` - Safely clear system logs with confirmation
  - `full_scan()` - Complete ClamAV system scan with logging
  - `custom_scan()` - Custom directory ClamAV scan

#### Development & Testing
- **CI/CD Pipeline**
  - GitHub Actions workflow for automated testing
  - ShellCheck linting on every push/PR
  - BATS test execution
  - Trivy security scanning
  - Bash syntax validation

- **Test Suite**
  - Comprehensive BATS tests for validation functions
  - 20+ test cases covering edge cases
  - Tests for ports, IPs, hostnames, and paths
  - Test documentation in `tests/README.md`

- **Configuration Management**
  - External configuration file support (`dsas.conf.example`)
  - Configurable installation directories
  - Auto-update settings
  - Security policy settings
  - Firewall behavior settings
  - ClamAV configuration options
  - Log rotation settings

- **Installation**
  - Professional installation script (`install.sh`)
  - Pre-installation checks (root, system, dependencies)
  - Automatic backup of existing installations
  - Safe file downloads with verification
  - Proper permissions setting
  - Colored output for better UX
  - Comprehensive error handling

#### Documentation
- **Bilingual README** (Portuguese/English)
  - Complete feature documentation
  - Installation instructions
  - Usage examples
  - Configuration guide
  - Testing guide
  - Security features documentation
  - Contributing guidelines

- **CHANGELOG** (this file)
  - Detailed version history
  - Categorized changes

### 🔧 Changed

- **Version Update**: 0.0.4 → 0.0.5
- **Error Handling**: Added `set -o pipefail` for better error detection
- **SSH Port Change**: Now validates port numbers and warns about privileged ports
- **Hostname Change**: Uses word boundaries in sed to prevent partial matches
- **MySQL Installation**: Secure password handling with validation
- **Firewall Menu**: Expanded from 8 to 10 options
- **Clear Rules**: Now requires confirmation and clears all chains (INPUT, nat, mangle)

### 🐛 Fixed

- **Critical Bug Fixes**
  - Fixed missing `view_logs()` function (menu option 10)
  - Fixed missing `clear_logs()` function (menu option 11)
  - Fixed missing `full_scan()` function (antivirus menu option 1)
  - Fixed missing `custom_scan()` function (antivirus menu option 2)

- **Security Vulnerabilities**
  - Fixed MySQL password exposure in process list
  - Fixed potential command injection in hostname change
  - Fixed unvalidated user input in firewall operations
  - Fixed unquoted variables in sed commands

- **Firewall Issues**
  - Fixed iptables rules not persisting after reboot
  - Added automatic persistence on rule changes

### 🚀 Performance

- Better error handling reduces failed operations
- Input validation prevents invalid commands from executing
- Automatic persistence reduces manual intervention

### 📚 Documentation

- Added comprehensive README in English and Portuguese
- Added CHANGELOG for version tracking
- Added test documentation
- Added inline comments for validation functions
- Added configuration file documentation

### 🔐 Security

- All user inputs now validated before use
- Command injection vulnerabilities patched
- MySQL passwords no longer visible in process list
- Firewall operations now warn about dangerous actions
- Hostname validation prevents malicious inputs

---

## [0.0.4] - 2024-08-31

### Added
- Initial stable release
- SSH management (port change, 2FA setup/removal, restart)
- Firewall management (block/unblock ports and IPs)
- LAMP stack installation
- ClamAV integration (stub functions)
- DNS configuration
- Hostname management
- System automation (cron scheduling)
- Auto-update mechanism
- Basic logging

### Known Issues (Fixed in 0.0.5)
- Missing implementation of `view_logs()`, `clear_logs()`, `full_scan()`, `custom_scan()`
- No input validation
- Insecure password handling
- iptables rules not persistent
- No automated testing
- No CI/CD pipeline

---

## Version History

- **0.0.5** (2025-12-05) - Major security and functionality update
- **0.0.4** (2024-08-31) - Initial stable release
- **0.0.3** - Beta testing
- **0.0.2** - Alpha release
- **0.0.1** - Initial development

---

For more information, visit: https://github.com/dolutech/Dolutech-Security-Automate-System
