# DSAS Tests

This directory contains automated tests for the Dolutech Security Automate System.

## Test Framework

Tests are written using [BATS (Bash Automated Testing System)](https://github.com/bats-core/bats-core).

## Running Tests

### Install BATS

**Ubuntu/Debian:**
```bash
sudo apt-get install bats
```

**RHEL/CentOS:**
```bash
sudo yum install bats
```

**macOS:**
```bash
brew install bats-core
```

### Run All Tests

```bash
cd tests
bats *.bats
```

### Run Specific Test File

```bash
bats tests/validation.bats
```

## Test Files

- `validation.bats` - Tests for input validation functions (ports, IPs, hostnames, paths)

## Writing New Tests

Follow the BATS syntax:

```bash
@test "description of test" {
    run your_command
    [ "$status" -eq 0 ]
}
```

## CI/CD Integration

Tests are automatically run via GitHub Actions on every push and pull request.
