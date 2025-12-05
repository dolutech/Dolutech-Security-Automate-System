#!/usr/bin/env bats

# Load the functions from the main script
setup() {
    # Source only the validation functions
    source <(grep -A 50 "^validate_port()" ../dsas.sh | sed '/^}/q')
    source <(grep -A 50 "^validate_ipv4()" ../dsas.sh | sed '/^}/q')
    source <(grep -A 50 "^validate_ipv6()" ../dsas.sh | sed '/^}/q')
    source <(grep -A 50 "^validate_hostname()" ../dsas.sh | sed '/^}/q')
    source <(grep -A 50 "^validate_path()" ../dsas.sh | sed '/^}/q')
}

# Test validate_port function
@test "validate_port: accepts valid port 80" {
    run validate_port 80
    [ "$status" -eq 0 ]
}

@test "validate_port: accepts valid port 443" {
    run validate_port 443
    [ "$status" -eq 0 ]
}

@test "validate_port: accepts valid port 65535" {
    run validate_port 65535
    [ "$status" -eq 0 ]
}

@test "validate_port: rejects port 0" {
    run validate_port 0
    [ "$status" -eq 1 ]
}

@test "validate_port: rejects port 65536" {
    run validate_port 65536
    [ "$status" -eq 1 ]
}

@test "validate_port: rejects negative port" {
    run validate_port -1
    [ "$status" -eq 1 ]
}

@test "validate_port: rejects non-numeric port" {
    run validate_port "abc"
    [ "$status" -eq 1 ]
}

# Test validate_ipv4 function
@test "validate_ipv4: accepts valid IP 192.168.1.1" {
    run validate_ipv4 "192.168.1.1"
    [ "$status" -eq 0 ]
}

@test "validate_ipv4: accepts valid IP 10.0.0.1" {
    run validate_ipv4 "10.0.0.1"
    [ "$status" -eq 0 ]
}

@test "validate_ipv4: rejects invalid IP 256.1.1.1" {
    run validate_ipv4 "256.1.1.1"
    [ "$status" -eq 1 ]
}

@test "validate_ipv4: rejects invalid IP format" {
    run validate_ipv4 "192.168.1"
    [ "$status" -eq 1 ]
}

@test "validate_ipv4: rejects malformed IP" {
    run validate_ipv4 "abc.def.ghi.jkl"
    [ "$status" -eq 1 ]
}

# Test validate_hostname function
@test "validate_hostname: accepts valid hostname 'server01'" {
    run validate_hostname "server01"
    [ "$status" -eq 0 ]
}

@test "validate_hostname: accepts valid FQDN 'web.example.com'" {
    run validate_hostname "web.example.com"
    [ "$status" -eq 0 ]
}

@test "validate_hostname: rejects hostname starting with hyphen" {
    run validate_hostname "-server"
    [ "$status" -eq 1 ]
}

@test "validate_hostname: rejects hostname with invalid characters" {
    run validate_hostname "server_01"
    [ "$status" -eq 1 ]
}

# Test validate_path function
@test "validate_path: accepts valid path '/var/log'" {
    run validate_path "/var/log"
    [ "$status" -eq 0 ]
}

@test "validate_path: rejects path with semicolon" {
    run validate_path "/var/log;rm -rf /"
    [ "$status" -eq 1 ]
}

@test "validate_path: rejects path with pipe" {
    run validate_path "/var/log | cat"
    [ "$status" -eq 1 ]
}

@test "validate_path: rejects path with command substitution" {
    run validate_path '/var/log/$(whoami)'
    [ "$status" -eq 1 ]
}
