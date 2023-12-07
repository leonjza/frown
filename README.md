# frown

Frown – an instrumentation challenge

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

Once the container is up and a host is configured, ssh in with `LC_ALL="C.utf8" ssh -L 27042:localhost:27042 remote-host -p2222`
