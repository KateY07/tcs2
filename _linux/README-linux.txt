TCS for Linux (x86_64, built on Ubuntu 24.04, needs glibc 2.39 or newer). Plain binaries, no installer, no runtime needed.

  tcs    controller:       tcs <host> health | exec "<python>" | upload <file>
  tcsd   controlled PC:    tcsd | tcsd pair
(tcsd is the same program as tcs started under another name; "tcs --tcsd ..." works too.)

Install:   install -m 755 tcs tcsd ~/.local/bin/        (or /usr/local/bin)

Keys (once per machine; nothing here generates keys, existing identities are never overwritten):
  controller:      mkdir -p -m 700 ~/.ssh && ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
  controlled PC:   mkdir -p -m 700 ~/.ssh && ssh-keygen -t ed25519 -N "" -f ~/.ssh/tcs_host_key

Pairing (first time):
  controlled PC:   tcsd pair                    shows a 6-digit code for one minute
  controller:      tcs pair <controlled-pc> <code>
  then:            tcs <controlled-pc> exec "print('hello')"

Fixed locations: ~/.ssh/id_ed25519, ~/.ssh/tcs_host_key, ~/.ssh/authorized_keys, ~/.ssh/tcs_known_hosts;
data and audit log in ~/.local/share/TCS/data (or $XDG_DATA_HOME/TCS/data). exec uses python3 from PATH
(--python <path> or TCS_PYTHON_EXE to change it). Open TCP port 10122 in the firewall of the controlled PC.
Run tcsd as a service with systemd: see tcsd.service. "--service" is the Windows service mode and is not used on Linux.
The Linux and Windows builds speak the same protocol and can control each other.
