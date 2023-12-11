# frown – an instrumentation challenge

A modified version of [tty-tetris-v2](https://github.com/Holixus/tty-tetris-v2) (modified source [here](ansible/files/docker-challenge/tty-tetris-v2/)) to include a Frida focussed instrumentation challenge.

```text
                        <! . . . . . . . . . .!>
                        <! . . . .[][] . . . .!>        cursor keys
    Lines:        4     <! . . . .[][] . . . .!>             or
    Figures:     18     <! . . . . . . . . . .!>
    Level:        1     <! . . . . . . . . . .!>           rotate
    Score:      313     <! . . . . .[Frida INFO] Listening on 127.0.0.1 TCP port 27042
    Port:     27042     <! . . . . . . . . . .!>            [w]
                        <! . . . . . . . . . .!>      <-[a] [s] [d]->
                        <! . . . . . . . . . .!>
             []         <! . . . . . . . . . .!>          [space]
         [][][]         <! . . . . . . . . . .!>             |
                        <! . . . . . . . . . .!>             V
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>        [p] - pause
                        <! . . . . . . . . . .!>        [q] - quit
                        <! . . . . .[] . . . .!>
                        <! . . . .[][][][] . .!>
                        <![][][][][][][][][] .!>
                        <![][][][][][][][][] .!>
                        <![][][] .[][][][][][]!>
                        <+--------------------+>
                          \/\/\/\/\/\/\/\/\/\/
```

## nuts and bolts

<img align="right" src="./images/logo.png" height="200" alt="beacon-pip-frame-proxy">

This challenge should be deployed to a fresh Ubuntu VM. There is an [ansible playbook](ansible/playbook.yml) that takes care of that.

Using systemd [socket activation](https://www.freedesktop.org/software/systemd/man/latest/systemd-socket-activate.html) a fresh docker instance per incoming SSH connection is spawned. Once authenticated via SSH, a game of Tetris spawns. This is where the challenge begins.

A second, long living container called `frown-service` should also run and serves as a flag server where keys found in the challenge binary are exchanged for a flag, if correct.

## solutions

See [solution](solution/README.md) for details on how to solve this challenge.

## development

There are two containers to develop. The flag service and the main challenge container. Both of them need to be connected to a network called `frownnet` (or if you want something else, update the rest with it) when started. Do that with:

```bash
docker network create frownnet
```

Next, build the relevant containers after changing to the `challenge` directory (a symlink actually) with:

```bash
docker build -t frown:local --progress=plain -f Dockerfile.dev . |& tee /dev/null
docker build -t frown-service:local --progress=plain -f Dockerfile.flag . |& tee /dev/null
```

Finally, run them. Start by booting the service container. It needs the name `frown-service` as the challenge binary will post there. Both should have the `frownnet` network.

```bash
docker run --rm --name frown-service -it --network frownnet frown-service:local
docker run --rm -it -p1234:1234 -p27042:27042 --network frownnet frown:local
```

Then, run the game with `tetris` in the challenge container.

To debug the challenge, set `HOST_DEBUG` from `CMakeLists.txt` to `ON` and start tetris with `gdbserver :1234 tetris`.

## production deployment

An ansible playbook targetting Ubuntu should take care of everything needed to get this up and running. Make sure you have a new host/vm and can ssh to it. The user you SSH with should also be able to use `sudo`. Then, change to the ansible/ directory and run `./play <target ip>` where `<target ip>` is the address for the host. If it's your first time running ansible, run the `./install-deps.sh` script first.

Example:

```text
❯ ./play.sh 192.168.167.135
targetting 192.168.167.135, will ask for sudo password
BECOME password:

PLAY [setup the frown challenge] **********************************

TASK [Gathering Facts] ********************************************
ok: [192.168.167.135]

...
```

## usage

Once the container is up and a host is configured, ssh in with `ssh -p24 'user@github'@remote-host`
