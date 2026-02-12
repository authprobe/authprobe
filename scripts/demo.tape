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
Sleep 12s

# Scroll down slowly (tune count + delay)
PageDown
Sleep 700ms
PageDown
Sleep 700ms
PageDown
Sleep 700ms
PageDown
Sleep 700ms

# Micro-scroll for fine positioning
Down 6
Sleep 500ms
Down 6

Sleep 2s
