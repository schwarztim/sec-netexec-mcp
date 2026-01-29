#!/usr/bin/env node
/**
 * NetExec MCP Server
 *
 * Provides MCP tools for executing NetExec (nxc) commands via SSH to a Kali Linux machine.
 * Supports SMB, WinRM, SSH, LDAP, MSSQL protocols and various modules.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_USER = process.env.SSH_USER || "";
const SSH_KEY = process.env.SSH_KEY || "";
const SSH_TIMEOUT = parseInt(process.env.SSH_TIMEOUT || "300", 10);

/**
 * Execute a command on the Kali machine via SSH
 */
async function executeOnKali(command: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  // Build SSH command
  const sshArgs: string[] = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=10",
    "-o", `ServerAliveInterval=60`,
  ];

  if (SSH_KEY) {
    sshArgs.push("-i", SSH_KEY);
  }

  const userHost = SSH_USER ? `${SSH_USER}@${KALI_HOST}` : KALI_HOST;
  const fullCommand = `ssh ${sshArgs.join(" ")} ${userHost} ${JSON.stringify(command)}`;

  try {
    const { stdout, stderr } = await execAsync(fullCommand, {
      timeout: SSH_TIMEOUT * 1000,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error: unknown) {
    const execError = error as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: execError.stdout || "",
      stderr: execError.stderr || String(error),
      exitCode: execError.code || 1,
    };
  }
}

/**
 * Build NetExec command with common options
 */
function buildNxcCommand(
  protocol: string,
  target: string,
  options: {
    username?: string;
    password?: string;
    hash?: string;
    domain?: string;
    localAuth?: boolean;
    module?: string;
    moduleOptions?: string;
    threads?: number;
    timeout?: number;
    extraArgs?: string;
  }
): string {
  const args: string[] = ["nxc", protocol, target];

  if (options.username) {
    args.push("-u", options.username);
  }

  if (options.password) {
    args.push("-p", options.password);
  }

  if (options.hash) {
    args.push("-H", options.hash);
  }

  if (options.domain) {
    args.push("-d", options.domain);
  }

  if (options.localAuth) {
    args.push("--local-auth");
  }

  if (options.module) {
    args.push("-M", options.module);
    if (options.moduleOptions) {
      args.push("-o", options.moduleOptions);
    }
  }

  if (options.threads) {
    args.push("-t", options.threads.toString());
  }

  if (options.timeout) {
    args.push("--timeout", options.timeout.toString());
  }

  if (options.extraArgs) {
    args.push(options.extraArgs);
  }

  return args.join(" ");
}

// Define all the tools
const tools: Tool[] = [
  {
    name: "nxc_smb",
    description: "Execute NetExec SMB protocol commands for Windows enumeration, credential validation, command execution, and credential dumping. Supports pass-the-hash attacks.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP, hostname, CIDR range, or file path containing targets",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash (format: LM:NT or :NT)",
        },
        domain: {
          type: "string",
          description: "Domain name for authentication",
        },
        localAuth: {
          type: "boolean",
          description: "Use local authentication instead of domain",
        },
        action: {
          type: "string",
          enum: ["enumerate", "shares", "users", "groups", "sessions", "disks", "loggedon", "computers", "sam", "lsa", "ntds", "exec-cmd", "exec-ps"],
          description: "Action to perform",
        },
        command: {
          type: "string",
          description: "Command to execute (for exec-cmd or exec-ps actions)",
        },
        module: {
          type: "string",
          description: "Module to run (e.g., lsassy, mimikatz, spider_plus)",
        },
        moduleOptions: {
          type: "string",
          description: "Module options (key=value format)",
        },
        continueOnSuccess: {
          type: "boolean",
          description: "Continue spraying after successful auth",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 100)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_winrm",
    description: "Execute NetExec WinRM protocol commands for remote Windows management and command execution.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP, hostname, CIDR range, or file path containing targets",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash",
        },
        domain: {
          type: "string",
          description: "Domain name for authentication",
        },
        action: {
          type: "string",
          enum: ["auth", "exec-cmd", "exec-ps", "sam", "lsa"],
          description: "Action to perform",
        },
        command: {
          type: "string",
          description: "Command to execute",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_ssh",
    description: "Execute NetExec SSH protocol commands for Linux/Unix enumeration and command execution.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP, hostname, CIDR range, or file path containing targets",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        keyFile: {
          type: "string",
          description: "Path to SSH private key file",
        },
        port: {
          type: "number",
          description: "SSH port (default: 22)",
        },
        command: {
          type: "string",
          description: "Command to execute on target",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_ldap",
    description: "Execute NetExec LDAP protocol commands for Active Directory enumeration, including users, groups, Kerberoasting, and BloodHound collection.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target domain controller IP or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash",
        },
        domain: {
          type: "string",
          description: "Domain name",
        },
        action: {
          type: "string",
          enum: ["users", "groups", "computers", "gmsa", "laps", "kerberoasting", "asreproast", "bloodhound", "trusts", "sid", "maq", "admin-count", "delegation"],
          description: "Action to perform",
        },
        bloodhoundCollection: {
          type: "string",
          description: "BloodHound collection method (All, DCOnly, etc.)",
        },
        module: {
          type: "string",
          description: "Module to run (e.g., adcs, daclread, maq)",
        },
        outputFile: {
          type: "string",
          description: "Output file path for results",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_mssql",
    description: "Execute NetExec MSSQL protocol commands for SQL Server enumeration and command execution.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target SQL Server IP or hostname",
        },
        username: {
          type: "string",
          description: "SQL username (or Windows user)",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        domain: {
          type: "string",
          description: "Domain for Windows authentication",
        },
        localAuth: {
          type: "boolean",
          description: "Use SQL Server authentication instead of Windows",
        },
        query: {
          type: "string",
          description: "SQL query to execute",
        },
        command: {
          type: "string",
          description: "OS command to execute via xp_cmdshell",
        },
        module: {
          type: "string",
          description: "Module to run (e.g., enum_logins, enum_impersonate)",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_rdp",
    description: "Execute NetExec RDP protocol commands for credential validation and screenshot capture.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP, hostname, or CIDR range",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash",
        },
        domain: {
          type: "string",
          description: "Domain name",
        },
        screenshot: {
          type: "boolean",
          description: "Take screenshot of RDP session",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_modules",
    description: "List or get information about available NetExec modules for a protocol.",
    inputSchema: {
      type: "object",
      properties: {
        protocol: {
          type: "string",
          enum: ["smb", "winrm", "ssh", "ldap", "mssql", "rdp", "wmi", "vnc", "ftp", "nfs"],
          description: "Protocol to list modules for",
        },
        moduleName: {
          type: "string",
          description: "Specific module name to get info about",
        },
      },
      required: ["protocol"],
    },
  },
  {
    name: "nxc_spray",
    description: "Perform password spraying attacks across multiple targets with configurable options.",
    inputSchema: {
      type: "object",
      properties: {
        protocol: {
          type: "string",
          enum: ["smb", "winrm", "ssh", "ldap", "mssql", "rdp"],
          description: "Protocol to use for spraying",
        },
        target: {
          type: "string",
          description: "Target IP, hostname, CIDR range, or file path",
        },
        userList: {
          type: "string",
          description: "Path to file containing usernames (one per line)",
        },
        username: {
          type: "string",
          description: "Single username to test",
        },
        passwordList: {
          type: "string",
          description: "Path to file containing passwords (one per line)",
        },
        password: {
          type: "string",
          description: "Single password to test",
        },
        domain: {
          type: "string",
          description: "Domain name",
        },
        continueOnSuccess: {
          type: "boolean",
          description: "Continue after finding valid credentials",
        },
        nobruteforce: {
          type: "boolean",
          description: "Avoid brute force by pairing user:pass from lists",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
        jitter: {
          type: "string",
          description: "Random delay between connections (e.g., '0-5')",
        },
      },
      required: ["protocol", "target"],
    },
  },
  {
    name: "nxc_shares",
    description: "Enumerate and interact with SMB shares on target systems.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP, hostname, or CIDR range",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash",
        },
        domain: {
          type: "string",
          description: "Domain name",
        },
        action: {
          type: "string",
          enum: ["list", "spider", "get", "put"],
          description: "Action to perform on shares",
        },
        share: {
          type: "string",
          description: "Specific share to interact with",
        },
        pattern: {
          type: "string",
          description: "File pattern for spider/search (e.g., '*.txt')",
        },
        depth: {
          type: "number",
          description: "Spider depth (default: 5)",
        },
        localFile: {
          type: "string",
          description: "Local file path for get/put operations",
        },
        remoteFile: {
          type: "string",
          description: "Remote file path for get/put operations",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_wmi",
    description: "Execute NetExec WMI protocol commands for Windows management and command execution.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP, hostname, or CIDR range",
        },
        username: {
          type: "string",
          description: "Username for authentication",
        },
        password: {
          type: "string",
          description: "Password for authentication",
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash",
        },
        domain: {
          type: "string",
          description: "Domain name",
        },
        command: {
          type: "string",
          description: "Command to execute",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nxc_raw",
    description: "Execute a raw NetExec command with full control over all arguments. Use for advanced scenarios not covered by other tools.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: "Full nxc command (without 'nxc' prefix)",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "nxc_database",
    description: "Query the NetExec database for stored credentials and hosts.",
    inputSchema: {
      type: "object",
      properties: {
        protocol: {
          type: "string",
          enum: ["smb", "winrm", "ssh", "ldap", "mssql", "rdp", "wmi"],
          description: "Protocol database to query",
        },
        action: {
          type: "string",
          enum: ["hosts", "creds", "export"],
          description: "Action to perform",
        },
        exportFormat: {
          type: "string",
          enum: ["csv", "json"],
          description: "Export format (for export action)",
        },
      },
      required: ["protocol", "action"],
    },
  },
];

// Tool handlers
async function handleNxcSmb(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  const action = args.action as string | undefined;
  switch (action) {
    case "shares":
      extraArgs = "--shares";
      break;
    case "users":
      extraArgs = "--users";
      break;
    case "groups":
      extraArgs = "--groups";
      break;
    case "sessions":
      extraArgs = "--sessions";
      break;
    case "disks":
      extraArgs = "--disks";
      break;
    case "loggedon":
      extraArgs = "--loggedon-users";
      break;
    case "computers":
      extraArgs = "--computers";
      break;
    case "sam":
      extraArgs = "--sam";
      break;
    case "lsa":
      extraArgs = "--lsa";
      break;
    case "ntds":
      extraArgs = "--ntds";
      break;
    case "exec-cmd":
      if (args.command) {
        extraArgs = `-x "${args.command}"`;
      }
      break;
    case "exec-ps":
      if (args.command) {
        extraArgs = `-X "${args.command}"`;
      }
      break;
  }

  if (args.continueOnSuccess) {
    extraArgs += " --continue-on-success";
  }

  const cmd = buildNxcCommand("smb", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    hash: args.hash as string | undefined,
    domain: args.domain as string | undefined,
    localAuth: args.localAuth as boolean | undefined,
    module: args.module as string | undefined,
    moduleOptions: args.moduleOptions as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcWinrm(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  const action = args.action as string | undefined;
  switch (action) {
    case "exec-cmd":
      if (args.command) {
        extraArgs = `-x "${args.command}"`;
      }
      break;
    case "exec-ps":
      if (args.command) {
        extraArgs = `-X "${args.command}"`;
      }
      break;
    case "sam":
      extraArgs = "--sam";
      break;
    case "lsa":
      extraArgs = "--lsa";
      break;
  }

  const cmd = buildNxcCommand("winrm", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    hash: args.hash as string | undefined,
    domain: args.domain as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcSsh(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  if (args.keyFile) {
    extraArgs += ` --key-file "${args.keyFile}"`;
  }

  if (args.port) {
    extraArgs += ` --port ${args.port}`;
  }

  if (args.command) {
    extraArgs += ` -x "${args.command}"`;
  }

  const cmd = buildNxcCommand("ssh", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcLdap(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  const action = args.action as string | undefined;
  switch (action) {
    case "users":
      extraArgs = "--users";
      break;
    case "groups":
      extraArgs = "--groups";
      break;
    case "computers":
      extraArgs = "--computers";
      break;
    case "gmsa":
      extraArgs = "--gmsa";
      break;
    case "laps":
      extraArgs = "-M laps";
      break;
    case "kerberoasting":
      extraArgs = "--kerberoasting";
      if (args.outputFile) {
        extraArgs += ` ${args.outputFile}`;
      }
      break;
    case "asreproast":
      extraArgs = "--asreproast";
      if (args.outputFile) {
        extraArgs += ` ${args.outputFile}`;
      }
      break;
    case "bloodhound":
      extraArgs = "--bloodhound";
      if (args.bloodhoundCollection) {
        extraArgs += ` -c ${args.bloodhoundCollection}`;
      } else {
        extraArgs += " -c All";
      }
      break;
    case "trusts":
      extraArgs = "-M enum_trusts";
      break;
    case "sid":
      extraArgs = "--get-sid";
      break;
    case "maq":
      extraArgs = "-M maq";
      break;
    case "admin-count":
      extraArgs = "--admin-count";
      break;
    case "delegation":
      extraArgs = "--trusted-for-delegation";
      break;
  }

  const cmd = buildNxcCommand("ldap", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    hash: args.hash as string | undefined,
    domain: args.domain as string | undefined,
    module: action ? undefined : (args.module as string | undefined),
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcMssql(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  if (args.query) {
    extraArgs = `-q "${args.query}"`;
  } else if (args.command) {
    extraArgs = `-x "${args.command}"`;
  }

  const cmd = buildNxcCommand("mssql", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    domain: args.domain as string | undefined,
    localAuth: args.localAuth as boolean | undefined,
    module: args.module as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcRdp(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  if (args.screenshot) {
    extraArgs = "--screenshot";
  }

  const cmd = buildNxcCommand("rdp", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    hash: args.hash as string | undefined,
    domain: args.domain as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcModules(args: Record<string, unknown>): Promise<string> {
  const protocol = args.protocol as string;
  let cmd: string;

  if (args.moduleName) {
    cmd = `nxc ${protocol} -M ${args.moduleName} --options`;
  } else {
    cmd = `nxc ${protocol} -L`;
  }

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcSpray(args: Record<string, unknown>): Promise<string> {
  const protocol = args.protocol as string;
  const target = args.target as string;
  let extraArgs = "";

  // Handle user specification
  if (args.userList) {
    extraArgs += ` -u "${args.userList}"`;
  } else if (args.username) {
    extraArgs += ` -u "${args.username}"`;
  }

  // Handle password specification
  if (args.passwordList) {
    extraArgs += ` -p "${args.passwordList}"`;
  } else if (args.password) {
    extraArgs += ` -p "${args.password}"`;
  }

  if (args.domain) {
    extraArgs += ` -d "${args.domain}"`;
  }

  if (args.continueOnSuccess) {
    extraArgs += " --continue-on-success";
  }

  if (args.nobruteforce) {
    extraArgs += " --no-bruteforce";
  }

  if (args.jitter) {
    extraArgs += ` --jitter ${args.jitter}`;
  }

  const cmd = `nxc ${protocol} ${target}${extraArgs}${args.threads ? ` -t ${args.threads}` : ""}`;

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcShares(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  const action = args.action as string | undefined;
  switch (action) {
    case "list":
      extraArgs = "--shares";
      break;
    case "spider":
      extraArgs = "-M spider_plus";
      if (args.share) {
        extraArgs += ` -o SHARE=${args.share}`;
      }
      if (args.pattern) {
        extraArgs += ` PATTERN=${args.pattern}`;
      }
      if (args.depth) {
        extraArgs += ` DEPTH=${args.depth}`;
      }
      break;
    case "get":
      if (args.share && args.remoteFile && args.localFile) {
        extraArgs = `--get-file "${args.remoteFile}" "${args.localFile}" --share "${args.share}"`;
      }
      break;
    case "put":
      if (args.share && args.localFile && args.remoteFile) {
        extraArgs = `--put-file "${args.localFile}" "${args.remoteFile}" --share "${args.share}"`;
      }
      break;
    default:
      extraArgs = "--shares";
  }

  const cmd = buildNxcCommand("smb", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    hash: args.hash as string | undefined,
    domain: args.domain as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcWmi(args: Record<string, unknown>): Promise<string> {
  const target = args.target as string;
  let extraArgs = "";

  if (args.command) {
    extraArgs = `-x "${args.command}"`;
  }

  const cmd = buildNxcCommand("wmi", target, {
    username: args.username as string | undefined,
    password: args.password as string | undefined,
    hash: args.hash as string | undefined,
    domain: args.domain as string | undefined,
    threads: args.threads as number | undefined,
    extraArgs,
  });

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcRaw(args: Record<string, unknown>): Promise<string> {
  const command = args.command as string;
  const cmd = `nxc ${command}`;

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

async function handleNxcDatabase(args: Record<string, unknown>): Promise<string> {
  const protocol = args.protocol as string;
  const action = args.action as string;
  let cmd: string;

  switch (action) {
    case "hosts":
      cmd = `nxcdb -p ${protocol}; echo '.hosts' | nxcdb -p ${protocol}`;
      break;
    case "creds":
      cmd = `echo '.creds' | nxcdb -p ${protocol}`;
      break;
    case "export":
      const format = args.exportFormat || "csv";
      cmd = `nxcdb -p ${protocol} --export ${format}`;
      break;
    default:
      cmd = `nxcdb -p ${protocol}`;
  }

  const result = await executeOnKali(cmd);
  return formatResult(cmd, result);
}

function formatResult(command: string, result: { stdout: string; stderr: string; exitCode: number }): string {
  let output = `Command: ${command}\n`;
  output += `Exit Code: ${result.exitCode}\n`;
  output += `\n--- STDOUT ---\n${result.stdout || "(empty)"}\n`;
  if (result.stderr) {
    output += `\n--- STDERR ---\n${result.stderr}\n`;
  }
  return output;
}

// Create and configure the server
const server = new Server(
  {
    name: "netexec-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: string;

    switch (name) {
      case "nxc_smb":
        result = await handleNxcSmb(args as Record<string, unknown>);
        break;
      case "nxc_winrm":
        result = await handleNxcWinrm(args as Record<string, unknown>);
        break;
      case "nxc_ssh":
        result = await handleNxcSsh(args as Record<string, unknown>);
        break;
      case "nxc_ldap":
        result = await handleNxcLdap(args as Record<string, unknown>);
        break;
      case "nxc_mssql":
        result = await handleNxcMssql(args as Record<string, unknown>);
        break;
      case "nxc_rdp":
        result = await handleNxcRdp(args as Record<string, unknown>);
        break;
      case "nxc_modules":
        result = await handleNxcModules(args as Record<string, unknown>);
        break;
      case "nxc_spray":
        result = await handleNxcSpray(args as Record<string, unknown>);
        break;
      case "nxc_shares":
        result = await handleNxcShares(args as Record<string, unknown>);
        break;
      case "nxc_wmi":
        result = await handleNxcWmi(args as Record<string, unknown>);
        break;
      case "nxc_raw":
        result = await handleNxcRaw(args as Record<string, unknown>);
        break;
      case "nxc_database":
        result = await handleNxcDatabase(args as Record<string, unknown>);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("NetExec MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
