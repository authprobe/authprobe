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

# Run the noisy command in a pager so we can scroll cleanly in the GIF
Type "authprobe scan https://compute.googleapis.com/mcp --explain --trace-failure | less -R"
Enter

# Give it a moment to start rendering output into less
Sleep 1.5s

# Scroll through output at a steady cadence
PageDown@200ms 12
Sleep 300ms
PageDown@200ms 12
Sleep 300ms
PageDown@200ms 12

# Exit pager
Type "q"
Sleep 300ms

Type "echo 'See README for full quickstart and troubleshooting'"
Enter
Sleep 2s


