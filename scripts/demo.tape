Output docs/assets/demo.gif
Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 700
Set Framerate 30
Set Theme "Catppuccin Mocha"

Type "authprobe --version"
Enter
Sleep 1s

Type "authprobe scan https://compute.googleapis.com/mcp --explain --trace-failure"
Enter
Sleep 10s

Type "echo 'See README for full quickstart and troubleshooting'"
Enter
Sleep 2s
