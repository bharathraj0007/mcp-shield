# VHS Tape Recording for mcp-shield CLI
# Generate GIF with: vhs demo.tape

Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 720
Set Padding 20
Set Theme "Catppuccin Mocha"

# 1. Inspect CLI Subcommands & Capabilities
Type "mcp-shield --help"
Sleep 500ms
Enter
Sleep 3s

# 2. Run Static Config & OWASP MCP Scanner
Type "mcp-shield scan"
Sleep 500ms
Enter
Sleep 4s

# 3. Preview Safe Secret Isolation into .env.mcp
Type "mcp-shield fix ~/.cursor/mcp.json --dry-run"
Sleep 500ms
Enter
Sleep 3s

# 4. Cryptographic Audit Log & Hash-Chain Verification
Type "mcp-shield audit --verify"
Sleep 500ms
Enter
Sleep 3s

# 5. Reproducible Benchmark Run
Type "npm run bench"
Sleep 500ms
Enter
Sleep 4s

Sleep 2s
