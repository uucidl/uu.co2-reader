# uu.co2-reader

Console based program to read and save CO2 concentrations and save
temperature measurements.

Supported platforms:
- Windows
- Linux
- Macos

Supported sensors:

All CO2 monitors based on the ZyAura ZGm053U product/chip.

# Usage

```
<program>[-o file.tsv]
This program collects co2 readings from Zyaura sensors.
Options:
  -o file.tsv: write to a tab-separated-value file (otherwise to standard output)
```

# Compilation

- build.bat for Windows
- co2_build_linux.sh for Linux
- co2_build_macos.sh for Macos

For all of these, a valid compiler is expected to be available the shell's
environment.

