# frown solution

There are many approaches to solve this challenge. There are two documented here. Both cases assumes the Frida port is finally open after solving the required number of lines.

Running the solver can be done with one of the following two commands:

```bash
python -m solution pinscore
python -m solution
```

## developing this agent

This project is a Frida agent, written in Typescript. The resultant agent should be transpiled using frida-compile. To start, change to the `frida/` directory and run `npm i` to install dependencies. If you just want the agent, run `npm run build`. If you want it to develop on it, you can have it continuously compile as you code with `npm run watch`.

## solutions

### brute forcing the flag

The most likely solution, this one involves reversing and instrumenting the game to retrieve the flag from the flag service. The expected flow  follows.

#### 1 - Initial recon

At first, you will SSH into a game instance with something like `ssh -p24 user@challenge` and be presented with a terminal version of Tetris. The game should be fully functional, so you can practice your tetris skills!

```text
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>        cursor keys
    Lines:        0     <! . . . .[][] . . . .!>             or
    Figures:      0     <! . . .[][] . . . . .!>
    Level:        1     <! . . . . . . . . . .!>           rotate
    Score:        0     <! . . . . . . . . . .!>             |
    Port:         0     <! . . . . . . . . . .!>            [w]
                        <! . . . . . . . . . .!>      <-[a] [s] [d]->
                        <! . . . . . . . . . .!>
             []         <! . . . . . . . . . .!>          [space]
         [][][]         <! . . . . . . . . . .!>             |
                        <! . . . . . . . . . .!>             V
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>        [p] - pause
                        <! . . . . . . . . . .!>        [q] - quit
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>
                        <+--------------------+>
                          \/\/\/\/\/\/\/\/\/\/
```

#### 2 - Starting Frida

Eventually, after solving a few lines, two things should happen. The `Port:` section should update from a `0` to `27042`. This is the port Frida will be listening on. The game board will be temporarily messed up, but will come right by itself when the next piece is generated.

```text
                        <! . . . . . . . . . .!>
                        <! . . . .[] . . . . .!>        cursor keys
    Lines:        3     <! . . .[][] . . . . .!>             or
    Figures:     15     <! . . . .[] . . . . .!>
    Level:        1     <! . . . . . . . . . .!>           rotate
    Score:      210     <! . . . . . . . . . .!>             |
    Port:     27042     <! . . . . . . . . . .!>            [w]
                        <! . . . . . . . . . .!>      <-[a] [s] [d]->
                        <! . . . . . . . . . .!>
         [][][][]       <! . . . . . . . . . .!>          [space]
                        <! . . . . . . . . . .!>             |
                        <! . . . . . . . . . .!>             V
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>        [p] - pause
                        <![] . . . . . . . . .!>        [q] - quit
                        <![] . . . . . . . . .!>
                        <![] . .[][] . . . . .!>
                        <![][][] .[][][][Frida INFO] Listening on 127.0.0.1 TCP port 27042      <! .[][][][][][][][][]!>
                  [][] .<! .[][][] .[][][][][]!>
                        <+--------------------+>
                          \/\/\/\/\/\/\/\/\/\/
```

At this point the player will have all of the hints needed to know that a new port is open. With it listening on localhost, it will require the player to use an SSH port forward with the `-L` flag to get access to the Frida port. That means, a new SSH command such as the following would be needed: `ssh -L 27042:localhost:27042 user@challenge`. Like before, with enough lines solved (more than 2 probably), Frida will start listening.

To confirm, installing the python `frida-tools` package, the player should be able to see the remote service available for instrumentation.

```text
❯ frida-ps -H localhost
PID  Name
--  ------
38  Gadget
```

Getting a score of more than 500 will have a new flag section show up on the right (with garbled output), but there isn't enough information about how this works at this stage of the challenge yet.

```text
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>        cursor keys
    Lines:       11     <! . . . .[] . . . . .!>             or
    Figures:     33     <! . . .[][] . . . . .!>
    Level:        2     <! . . . .[] . . . . .!>           rotate
    Score:      535     <! . . . . . . . . . .!>             |
    Port:     27042     <! . . . . . . . . . .!>            [w]
                        <! . . . . . . . . . .!>      <-[a] [s] [d]->
                        <! . . . . . . . . . .!>
         [][]           <! . . . . . . . . . .!>          [space]
           [][]         <! . . . . . . . . . .!>             |
                        <! . . . . . . . . . .!>             V
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>        [p] - pause
                        <! . . . . . . . . . .!>        [q] - quit
                        <! . . . . . . . . . .!>
                        <! . . . . . . . . . .!>       [flag] N
                        <![] . . . .[] . .[][]!>      !OM!     !J
                        <![] .[][][][][][][][]!>          N!
                        <![][][][] .[][][][][]!>            MMM
                        <+--------------------+>
                          \/\/\/\/\/\/\/\/\/\/
```

#### 3 - Getting the binary

With only access to the Frida DBUS socket, a Frida script can be written to enumerate where the binary for the main process lives on disk as well as a script to download it to the players computer. There are many ways to achieve this, but most of them will include writing an agent and client to run the agent in the remote process.

To find the location of the binary:

```text
❯ frida -H localhost Gadget
     ____
    / _  |   Frida 16.1.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to localhost (id=socket@localhost)
Attaching...
[Remote::Gadget ]-> Process.mainModule
{
    "base": "0x558f780f3000",
    "name": "tetris",
    "path": "/usr/local/bin/tetris",
    "size": 29920
}
```

Knowing the binary is at `/usr/local/bin/tetris`, the file can be downloaded using the Node `fs` module and `fs.readFileSync("/usr/local/bin/tetris")`. See this agent's source code for a complete example.

#### 4 - Analysing the binary

With the binary on the players computer, opening in a decompiler of choice should start off a reversing session. The binary is not small, and might take a while to find where exactly interesting code lives. The player should find a call to `dlopen` with the argument of `libttyris.so`. This library used to run a `flag_key` function which should be easily found in the downloaded binary. Finally, the library is unloaded, so when a player uses the Frida `Process.enumerateModules()` API, `libttyris` won't show up there.

Extract of the relevant function is below. Note the calls to `dlopen`, `dlsym` and `dlcose`:

```c
    if (*(int32_t *)(arg1 + 0x80) != _data.00007144 && _data.00007144 <= *(int32_t *)(arg1 + 0x80)) {
        uStack_110 = 0x2e27;
        iVar3 = dlopen("libttyris.so", 2);
        if (iVar3 == 0) {
            uStack_110 = 0x2ea6;
            puVar2 = (undefined *)dlerror();
            pcVar5 = " [flag] not found %s";
        } else {
            uStack_110 = 0x2e3e;
            pcVar1 = (code *)dlsym(iVar3, "flag_key");
            uStack_110 = 0x2e4b;
            puStack_100 = (undefined4 *)malloc(100);
            puVar6 = puStack_100;
            for (iVar4 = 0x19; iVar4 != 0; iVar4 = iVar4 + -1) {
                *puVar6 = 0;
                puVar6 = puVar6 + (uint64_t)uVar7 * -2 + 1;
            }
            uStack_110 = 0x2e70;
            (*pcVar1)(*(undefined4 *)(arg1 + 0x80), puStack_100, 100);
            puVar2 = auStack_ec;
            uStack_110 = 0x2e7f;
            dlclose(iVar3);
            uStack_110 = 0x2e95;
            fcn.00001d2f((int64_t)"http://frown-service/", puStack_100, (int64_t)puVar2);
            pcVar5 = " [flag] %s";
        }
        uStack_110 = 0x2eba;
        sprintf(auStack_9c, pcVar5, puVar2);
    }
```

The handle to `flag_key` takes an offset of the first argument of the caller function as argument, along with an `malloc`'d pointer.

Also worth noting is the URL <http://frown-service/>. Inspecting the function call that takes this URL as an argument should reveal what looks like a cURL related call to make an HTTP request.

```c
void fcn.00001d2f(int64_t arg1, void *arg2, int64_t arg3)
{
    int32_t iVar1;
    int64_t iVar2;
    undefined8 uVar3;
    int64_t var_20h;
    
    var_20h = arg3;
    iVar2 = curl_easy_init();
    if (iVar2 != 0) {
        curl_easy_setopt(iVar2, data.00002712, arg1);
        curl_easy_setopt(iVar2, data.0000271f, arg2);
        fcn.00001d13(iVar2, data.00004e2b);
        curl_easy_setopt();
        curl_easy_setopt(iVar2, data.00002711, &var_20h);
        iVar1 = curl_easy_perform(iVar2);
        if (iVar1 != 0) {
            uVar3 = curl_easy_strerror(iVar1);
            fprintf(_stderr, "curl_easy_perform() failed: %s\n", uVar3);
            var_20h = 0;
        }
        curl_easy_cleanup(iVar2);
    }
    return;
}
```

#### 5 - Getting libttyris

This part shouldn't be _too_ hard. The player can either crawl the filesystem with some instrumentation (effectively using `fs.readdirSync(path)` or any C equivalent), or by blocking the call to `dlcose` actually unloading the shared library and inspecting the loaded modules for information. Blocking the `dlclose` can be done with:

```javascript
    Interceptor.replace(Module.getExportByName(null, "dlclose"), new NativeCallback((handle) => {
      return 0;
    }, 'int', ['pointer']));
```

With that running, the player can search for `libttyris` in `Process.enumerateModules()` to learn the path:

```text
{
  'base': '0x7f4ad4141000',
  'name': 'libttyris.so',
  'path': '/usr/lib/libttyris.so',
  'size': 16408
}
```

Then, using the same technique as before, download the shared library and reverse it. The library is really simple with an interesting function called `flag_key` (which is the symbol used in the caller binary). An XOR operation is performed against a static buffer.

```c
int64_t flag_key(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4)
{
    uint64_t uVar1;
    uint64_t uVar2;
    
    uVar2 = 0;
    while( true ) {
        uVar1 = fcn.00001030();
        if ((uVar1 <= uVar2) || ((uint64_t)(int64_t)(int32_t)arg3 <= uVar2)) break;
        *(uint8_t *)(arg2 + uVar2) = (uint8_t)*(undefined4 *)(uVar2 * 4 + 0x2000) ^ (uint8_t)arg1;
        uVar2 = uVar2 + 1;
    }
    return arg4;
}
```

#### 6 - Using flag_key

A few options are available at this point. Depending on your reversing skills you may realise that the current score is passed to `flag_key()` as the first argument. If not, you can write some instrumentation `Interceptor.attach` to see the arguments passed to the function. Doing this is not trivial, as you'd need to hook `dlsym()` to learn the offset of `flag_key` and then hook on that pointer. Not impossible :)

A simpler method to use `flag_key` would be to use the Frida `Module.load()` API to get a handle on the shared library, then calling `flag_key` yourself.

```javascript
    const m = Module.load("libttyris.so");
    const flag_key_ptr = m.getExportByName("flag_key");

    const flag_key = new NativeFunction(flag_key_ptr, 'void', ['int', 'pointer', 'int']);
    const flag_len = 100;
    const flag = Memory.alloc(flag_len);

    flag_key(key, flag, flag_len);

    const flag_value = flag.readUtf8String();
    return flag_value;
```

Of course, some reversing and debugging will be needed to get this one right.

#### 7 - Submitting the key for a flag

The final piece of the puzzle is to get the actual flag using the correct key. Whatever `flag_key` returns needs to be posted to a web service living next to the Tetris game at `http://frown-service`. This can be done either by instrumenting the function call that reaches out to cURL, or using a Node http client.

The cURL instrumentation way would be to first watch how it is invoked. Determine the offset to the function that does the cURL call and watch the arguments both before and after the function call. Either by reversing, or by experimenting with function calls, the player will learn the first two arguments are the URL and the incoming key, with the response written to the third argument. Instrumentation to watch this method would be:

```javascript
    const curl = Process.mainModule.base.add(0x00001d2f);
    Interceptor.attach(curl, {
      onEnter(args) {
        send(`curl->() arg0="${args[0].readUtf8String()}" arg1=${args[1].readUtf8String()}`);
        this.response = args[2];
      },
      onLeave(retval) {
        send(`curl<-() arg3="${this.response.readUtf8String()}"`);
      }
    });
```

The result being something like this while playing the game:

```text
❯ python -m solution watchcurl
[enter] to exit ...curl->() arg0="http://frown-service/" arg1=TWSVQSZVWRTRSVT
curl<-() arg3="key too short
"
curl->() arg0="http://frown-service/" arg1=RQUPWU\PQ
curl<-() arg3="key too short
"
curl->() arg0="http://frown-service/" arg1=MNJOHJCONKMKJOMOBBK
curl<-() arg3=""
```

Knowing how the function works, this can instrumented to send our own key using the same method.

```javascript
    const curl_ptr = Process.mainModule.base.add(0x00001d2f);

    const curl = new NativeFunction(curl_ptr, 'void', ['pointer', 'pointer', 'pointer']);
    const response = Memory.alloc(100);

    const url = Memory.allocUtf8String("http://frown-service/");
    const key_ptr = Memory.allocUtf8String(key.toString());

    curl(url, key_ptr, response);

    return response.readUtf8String();
```

For an alternative method using a Node HTTP client, check the solution agent source.

#### 8 - bruting the key, getting the flag

With the ability to generate a key based on a score integer, and to submit that to the flag service, we can combine them by looping a range of integers, submitting each to the web service via our instrumented function and checking for the `flag` keyword.

```python
for x in range(0, 40000):
 if 'flag' in (flag := api.usecurl(api.flagkey(x))):
  print(f'key: {x}, flag: {flag}')
  break
```

### pinning the score

An alternative, mostly cosmetic way to solve the challenge would be to update the score the game has to `31337` to have the game show the flag as part of its output.

The start of the challenge would follow exactly the same way as the previous solve all the way to reversing (and possibly solving) the challenge. However, to have the flag show up in the game, you'd need to traverse a nested C structure to find the score value and update it.

TODO: complete the writeup here.

```javascript
    const tetris_refresh = Process.mainModule.base.add(0x00002dc8);
    Interceptor.attach(tetris_refresh, {
      onEnter(args) {
        const tetris_t = args[0];
        const score_t = tetris_t.add(Process.pointerSize * 14);
        const score_ptr = score_t.add(4 * 4);

        send(`tetris_t=${tetris_t}, score_t=${score_t}, score=${score_ptr.readInt()}`);

        score_ptr.writeInt(31337);
      }
    });
```
