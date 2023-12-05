import fs from "fs";

rpc.exports = {
  dir: (p: string) => fs.readdirSync(p),
  binpath: () => Process.mainModule.path,
  getfile: (p: string) => fs.readFileSync(p),
  watchdlopen: () => {
    Interceptor.attach(Module.getExportByName(null, "dlopen"), {
      onEnter(args) {
        const path = args[0].readUtf8String();
        const flags = args[1].toInt32();
        send(`dlopen() path="${path}", flags="${flags}"`);
      }
    });
  },
  blockdlclose: () => {
    Interceptor.replace(Module.getExportByName(null, "dlclose"), new NativeCallback((handle) => {
      send(`dlclose() handle="${handle}"`);
      return 0;
    }, 'int', ['pointer']));
  },
  flagkey: (key: number) => {
    const m = Module.load("libttyris.so");
    const flag_key_ptr = m.getExportByName("flag_key");

    const flag_key = new NativeFunction(flag_key_ptr, 'void', ['int', 'pointer', 'int']);
    const flag_len = Process.pointerSize * 100;
    const flag = Memory.alloc(flag_len);

    flag_key(key, flag, flag_len);

    const flag_value = flag.readUtf8String();
    return flag_value;
  },
};
