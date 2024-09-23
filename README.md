# System Hardening Script

This script is designed to enhance system security by hardening GRUB, kernel, and network settings. It also restricts services and access to align with ANSSI v2 guidelines.

## Features

- **GRUB Hardening:** Updates GRUB configurations to improve boot security.
- **Kernel Hardening:** Configures kernel settings to bolster system protection.
- **Network Hardening:** Adjusts network settings to mitigate potential threats.
- **Service Restrictions:** Disables unnecessary services to reduce attack surfaces.
- **Access Controls:** Implements stricter access controls for enhanced security.

## Requirements

- Linux-based operating system
- Root or sudo access

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-repository/system-hardening-script.git
    ```

2. Navigate to the script directory:
    ```bash
    cd system-hardening-script
    ```

3. Make the script executable:
    ```bash
    chmod +x hardening-script.sh
    ```

## Usage

Run the script with root or sudo privileges:
    ```bash
    sudo ./hardening-script.sh
    ```

## Notes

- Review the script before execution to understand the changes being applied.
- Backup important data before applying system hardening changes.

## Compliance

The script follows the [ANSSI v2 guidelines](https://cyber.gouv.fr/sites/default/files/2018/10/guide_anssi_secure_admin_is_pa_022_en_v2.pdf) for system hardening.
