Abhimanyu X — installable source distribution (data ISO)

This is a plain ISO 9660 data disc, not a bootable image. Mount it (double-click
on Mac/Windows, or `mount` on Linux) and run the installer for your platform:

  Mac / Linux:   ./install.sh
  Windows:       install.bat

Both scripts copy the abhimanyux/ folder to a writable location (default:
your home directory), create a Python virtual environment, and install
dependencies. See abhimanyux/README.md after installing for usage,
architecture, and — importantly — the "Known limitations" section: this is
a research prototype, not a certified or production-hardened tool.

Contents:
  abhimanyux/     Full source: REWIND, ANVIL, Verifier, Immune Memory,
                  Watch engine, tests, plus the platform/cli/deploy/iso/usb
                  experimental scaffolding (see abhimanyux/README.md for
                  which parts are tested and which are not).
  install.sh      Mac/Linux installer
  install.bat     Windows installer
