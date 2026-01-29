# NetExec MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)
[![NetExec](https://img.shields.io/badge/NetExec-Network%20Execution-red)](https://www.netexec.wiki/)

A Model Context Protocol (MCP) server that provides AI assistants with access to [NetExec](https://github.com/Pennyw0rth/NetExec) (nxc), the powerful network execution and penetration testing tool formerly known as CrackMapExec.

## Features

This MCP server enables AI assistants to execute NetExec commands via SSH to a Kali Linux machine, supporting:

| Protocol | Capabilities |
|----------|-------------|
| **SMB** | Windows enumeration, credential dumping (SAM/LSA/NTDS), command execution, pass-the-hash |
| **WinRM** | Remote Windows management, PowerShell execution, credential dumping |
| **SSH** | Linux/Unix authentication, key-based auth, remote command execution |
| **LDAP** | Active Directory enumeration, Kerberoasting, ASREPRoast, BloodHound collection |
| **MSSQL** | SQL Server queries, xp_cmdshell execution, login enumeration |
| **RDP** | Credential validation, screenshot capture |
| **WMI** | Windows Management Instrumentation command execution |

Additional features:
- Password spraying across all protocols
- Module management and execution
- SMB share enumeration and file operations
- NetExec credential database queries

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux machine with NetExec installed
- SSH key-based authentication (recommended) or password

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-netexec-mcp.git
cd sec-netexec-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname or IP for Kali machine | `kali` |
| `SSH_USER` | SSH username | (none) |
| `SSH_KEY` | Path to SSH private key file | (none) |
| `SSH_TIMEOUT` | Command timeout in seconds | `300` |

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "netexec": {
      "command": "node",
      "args": ["/path/to/sec-netexec-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-host",
        "SSH_USER": "kali",
        "SSH_KEY": "/path/to/ssh/key"
      }
    }
  }
}
```

## Available Tools

### `nxc_smb`
SMB protocol operations including enumeration, share listing, user/group/session enumeration, credential dumping (SAM, LSA, NTDS), and command execution.

### `nxc_winrm`
WinRM remote management for authentication testing, cmd/PowerShell execution, and credential dumping.

### `nxc_ssh`
SSH protocol for authentication testing, key-based auth, and remote command execution.

### `nxc_ldap`
LDAP/Active Directory operations including user/group/computer enumeration, Kerberoasting, ASREPRoast, BloodHound collection, and trust enumeration.

### `nxc_mssql`
SQL Server operations including queries, xp_cmdshell execution, and login enumeration.

### `nxc_rdp`
RDP credential validation and screenshot capture.

### `nxc_wmi`
WMI-based command execution on Windows targets.

### `nxc_modules`
List and query available NetExec modules for each protocol.

### `nxc_spray`
Password spraying with configurable options including user/password lists, jitter, and continue-on-success.

### `nxc_shares`
SMB share enumeration and file operations (spider, get, put).

### `nxc_raw`
Execute raw NetExec commands for advanced scenarios not covered by other tools.

### `nxc_database`
Query the NetExec credential database for stored hosts and credentials.

## Usage Examples

### Enumerate SMB Hosts
```json
{
  "tool": "nxc_smb",
  "arguments": {
    "target": "192.168.1.0/24"
  }
}
```

### List Shares with Credentials
```json
{
  "tool": "nxc_smb",
  "arguments": {
    "target": "192.168.1.10",
    "username": "admin",
    "password": "P@ssw0rd",
    "domain": "CORP",
    "action": "shares"
  }
}
```

### Pass-the-Hash Attack
```json
{
  "tool": "nxc_smb",
  "arguments": {
    "target": "192.168.1.10",
    "username": "admin",
    "hash": "aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76",
    "domain": "CORP",
    "action": "shares"
  }
}
```

### Password Spray
```json
{
  "tool": "nxc_spray",
  "arguments": {
    "protocol": "smb",
    "target": "192.168.1.0/24",
    "userList": "/tmp/users.txt",
    "password": "Summer2024!",
    "domain": "CORP",
    "continueOnSuccess": true
  }
}
```

### BloodHound Collection
```json
{
  "tool": "nxc_ldap",
  "arguments": {
    "target": "dc01.corp.local",
    "username": "user",
    "password": "password",
    "domain": "CORP",
    "action": "bloodhound",
    "bloodhoundCollection": "All"
  }
}
```

### Dump NTDS from Domain Controller
```json
{
  "tool": "nxc_smb",
  "arguments": {
    "target": "dc01.corp.local",
    "username": "admin",
    "password": "P@ssw0rd",
    "domain": "CORP",
    "action": "ntds"
  }
}
```

## Security Considerations

This tool is intended for **authorized security testing only**. Always ensure you have:

- Written authorization to test target systems
- Proper scope definition for penetration testing engagements
- Compliance with applicable laws and regulations

**Never use this tool against systems you do not have explicit permission to test.**

## Development

```bash
# Watch mode for development
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│   AI Assistant  │────▶│  NetExec MCP     │────▶│  Kali Linux    │
│  (Claude, etc.) │     │  Server (Node.js)│ SSH │  (nxc)         │
└─────────────────┘     └──────────────────┘     └────────────────┘
                              │
                              │ stdio
                              ▼
                        ┌──────────────┐
                        │ MCP Protocol │
                        └──────────────┘
```

## References

- [NetExec Official Wiki](https://www.netexec.wiki/)
- [NetExec GitHub Repository](https://github.com/Pennyw0rth/NetExec)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [NetExec Cheat Sheet](https://www.stationx.net/netexec-cheat-sheet/)
- [Kali Linux NetExec](https://www.kali.org/tools/netexec/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Users are responsible for ensuring compliance with all applicable laws and regulations.
