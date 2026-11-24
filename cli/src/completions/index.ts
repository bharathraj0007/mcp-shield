export type ShellType = "bash" | "zsh" | "fish" | "powershell";

export function generateCompletions(shell: string): string {
  const normalized = shell.toLowerCase().trim();

  switch (normalized) {
    case "bash":
      return `_mcp_shield_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    commands="scan proxy policy init fix audit rules baseline completions"

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "\${commands}" -- \${cur}) )
        return 0
    fi

    case "\${COMP_WORDS[1]}" in
        scan)
            COMPREPLY=( $(compgen -W "--json --format --policy --ci --fail-on --baseline --baseline-update --changed-only --output" -- \${cur}) )
            return 0
            ;;
        proxy)
            COMPREPLY=( $(compgen -W "--policy --fail-closed --passthrough --framing --rug-pull --rug-pull-baseline --rug-pull-mode" -- \${cur}) )
            return 0
            ;;
        policy)
            COMPREPLY=( $(compgen -W "validate schema" -- \${cur}) )
            return 0
            ;;
        init)
            COMPREPLY=( $(compgen -W "--policy --template" -- \${cur}) )
            return 0
            ;;
        fix)
            COMPREPLY=( $(compgen -W "--dry-run --yes --env-file --rollback --json" -- \${cur}) )
            return 0
            ;;
        audit)
            COMPREPLY=( $(compgen -W "--verify --json --hmac-key --export --tail" -- \${cur}) )
            return 0
            ;;
        rules)
            COMPREPLY=( $(compgen -W "--json" -- \${cur}) )
            return 0
            ;;
        baseline)
            COMPREPLY=( $(compgen -W "--json" -- \${cur}) )
            return 0
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- \${cur}) )
            return 0
            ;;
    esac
}
complete -F _mcp_shield_completions mcp-shield
`;

    case "zsh":
      return `#compdef mcp-shield
_mcp_shield() {
  local -a commands
  commands=(
    'scan:Scan local MCP configurations for security risks'
    'proxy:Run stdio JSON-RPC firewall proxy'
    'policy:Validate policy or generate JSON schema'
    'init:Initialize starter policy.yaml'
    'fix:Safely extract hardcoded secrets into .env.mcp'
    'audit:Inspect or verify tamper-evident audit log'
    'rules:List all supported security detection rules'
    'baseline:Inspect findings baseline'
    'completions:Generate shell completion script'
  )
  _describe 'command' commands
}
compdef _mcp_shield mcp-shield
`;

    case "fish":
      return `complete -c mcp-shield -n "__fish_use_subcommand" -a "scan" -d "Scan local MCP configurations"
complete -c mcp-shield -n "__fish_use_subcommand" -a "proxy" -d "Run stdio JSON-RPC firewall proxy"
complete -c mcp-shield -n "__fish_use_subcommand" -a "policy" -d "Validate policy or view schema"
complete -c mcp-shield -n "__fish_use_subcommand" -a "init" -d "Initialize starter policy.yaml"
complete -c mcp-shield -n "__fish_use_subcommand" -a "fix" -d "Safely extract hardcoded secrets"
complete -c mcp-shield -n "__fish_use_subcommand" -a "audit" -d "Inspect or verify audit log"
complete -c mcp-shield -n "__fish_use_subcommand" -a "rules" -d "List security detection rules"
complete -c mcp-shield -n "__fish_use_subcommand" -a "baseline" -d "Inspect findings baseline"
complete -c mcp-shield -n "__fish_use_subcommand" -a "completions" -d "Generate shell completion script"
`;

    case "powershell":
      return `Register-ArgumentCompleter -Native -CommandName mcp-shield -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $subcommands = @('scan', 'proxy', 'policy', 'init', 'fix', 'audit', 'rules', 'baseline', 'completions')
    $subcommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
`;

    default:
      throw new Error(`Unsupported shell: "${shell}". Supported shells: bash, zsh, fish, powershell.`);
  }
}
