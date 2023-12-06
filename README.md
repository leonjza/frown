# frown

Frown – an instrumentation challenge

## development

Build the challenge container by changing to `challenge` (a symlink), then:

```bash
docker build -t frown:local --progress=plain -f Dockerfile.dev . |& tee /dev/null
```

Run with:

```bash
docker run --rm -it -p1234:1234 -p27042:27042 frown:local
```

Then, run the game with `tetris`.

## production deployment

An ansible playbook targetting Ubuntu should take care of everything needed to get this up and running. Make sure you have a new host/vm and can ssh to it. The user you SSH with should also be able to use `sudo`. Then, change to the ansible/ directory and run `./play <target ip>` where `<target ip>` is the address for the host.

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

Once the container is up (assuming non socket-activated, local development setup), ssh in with `LC_ALL="C.utf8" ssh -L 27042:localhost:27042 localhost -p2222`
