```
██╗███╗   ██╗███████╗ ██████╗ ███╗   ███╗███╗   ██╗██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
██║████╗  ██║██╔════╝██╔═══██╗████╗ ████║████╗  ██║██║██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██║██╔██╗ ██║███████╗██║   ██║██╔████╔██║██╔██╗ ██║██║███████║███████║██║     █████╔╝
██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║╚██╗██║██║██╔══██║██╔══██║██║     ██╔═██╗
██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

Author: @leonjza

# Challenge details

| Contest | Challenge | Category | Base difficulty |
| :---: | :---: | :---: | :---: |
| INS23 | FROWN | Reverse | MEDIUM |

# Development progress

- [x] Build it
- [ ] Tweak game parameters
- [ ] Ensure binaries are stripped and `-Os`
- [ ] Check publishing via ansible
- [ ] Determine access method (removing pin to Github accounts)
- [ ] Confirm resource needs

# Requirements

An Ubuntu host with TCP/24 open for players to SSH into. 2GB of RAM should be enough.

# Deployment Instructions

Change to the `ansible/` directory. If this is your first time running ansible, install the dependencies (using a new python virtual environment) with `./install-deps.sh`. Then, once you can SSH to the target host where the challenge will be deployed, run the playbook with `./play <target ip>`.

# Description

How good is your Tetris? Connect, win, and reveal the flag!

# Provided assets

No assets. Just a remote host to SSH into.

# Flag

```text
flag{y0u_c4nt_h1d3_fr0m_fr333da}
```

# Remarks / Anticipated FAQ

- How can I connect to the Frida port?
You are SSH-ing, what does the `-L` flag do?

- How can I reverse a binary I don't have?
Write some Frida script to get it.

- I have the key, but can't reach the flag service.
Again, `-L`, or, Frida can make HTTP calls when scripted correctly.

# Internal presentation

N/A

# Writeup

## Abstract

This challenge is meant to be solved by interacting with the Frida DBUS port that opens up after solving two lines in a classic game of Tetris. The Frida Javascript API documentation is a good place to start to learn how to instrument binaries, and can be found [here](https://frida.re/docs/javascript-api/).

## Exploitation

### Tools used in the writeup

- Frida

### Reconnaissance

Once connected via SSH, the player will be presented with a terminal rendered version of classic Tetris. At first glance, nothing obvious would happen. However, once the score board has tracked mroe than two lines solved, the `Port` section in the scoreboard will update to `27042`, with a brief message of `Frida Listening` displayed on the screen as a hint that a new port is open. This is where the challenge effectively starts.

In addition, once a score of 500 or more is reached, the keyboard section will display a flag value, which will only correct once a specific score has been reached. This is an optional way of revealing the flag once solved.

### Exploitation steps

```
=> For each step of the challenge describe:
- What is the vulnerability?
- How can the player find out that there is a vulnerability (source code, weird behaviour, information leak, etc.)?
- How to exploit the vulnerability?
```

- SSH to the service
- Play the game to load Frida
- Connect a frida client
- Enumerate the application
- Download the main binary to your local machine via a frida script. use either frida-fs, or a script that implements `fopen()` et al.
- Reverse the application to discover the flag key calculation in `tetris_refresh`.
-

### Exploitation script

See [solution/](solution).
