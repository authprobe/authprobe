
Output docs/assets/demo.gif

Set Width 1200
Set Height 650
Set FontSize 32
Set TypingSpeed 60ms
Set WaitTimeout 3m

# Make prompt deterministic
Type "export PS1='DEMO>'"
Enter
Sleep 200ms

Type "cd /mnt/vol2/authprobe"
Enter

Type "rm -f /tmp/authprobe-report.md"
Enter

Type "authprobe scan https://aws-mcp.us-east-1.api.aws/mcp --timeout 4 --md /tmp/authprobe-report.md"
Enter

# Wait for scan to fully complete (prompt returns)
Wait+Line /DEMO>$/

Type "sed -n '/^Primary Finding/,/^$/p' /tmp/authprobe-report.md"
Enter

Sleep 2s

