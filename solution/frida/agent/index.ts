import fs from "fs";
import http from "http";

rpc.exports = {
  dir: (p: string) => fs.readdirSync(p),
  binpath: () => Process.mainModule.path,
  getfile: (p: string) => fs.readFileSync(p),
  modules: () => Process.enumerateModules(),
  watchoffset: (a: number) => {
    const offset = Process.mainModule.base.add(ptr(a));
    send(`watching func at ${a}. offset="${offset}"`);
    Interceptor.attach(offset, {
      onEnter(args) {
        send(`watchfunc: ${a} called. arg[0]="${args[0]}"`);
      }
    });
  },
  watchlibs: () => {
    Interceptor.attach(Module.getExportByName(null, "dlopen"), {
      onEnter(args) {
        const path = args[0].readUtf8String();
        const flags = args[1].toInt32();
        send(`dlopen() path="${path}", flags="${flags}"`);
      }
    });

    Interceptor.attach(Module.getExportByName(null, "dlclose"), {
      onEnter(args) {
        const handle = args[0];
        send(`dlclose() handle="${handle}"`);
      }
    });
  },
  blockdlclose: () => {
    Interceptor.replace(Module.getExportByName(null, "dlclose"), new NativeCallback((handle) => {
      return 0;
    }, 'int', ['pointer']));
  },
  pinscore: () => {
    const tetris_refresh = Process.mainModule.base.add(0x00002dc8);
    Interceptor.attach(tetris_refresh, {
      onEnter(args) {
        const tetris_t = args[0];
        const score_t = tetris_t.add(Process.pointerSize * 14);
        const score_ptr = score_t.add(4 * 4);

        send(`tetris_t=${tetris_t}, score_t=${score_t}, score=${score_ptr.readInt()}`);

        score_ptr.writeInt(9197);
      }
    });
  },
  flagkey: (key: number) => {
    const m = Module.load("libttyris.so");
    const flag_key_ptr = m.getExportByName("flag_key");

    const flag_key = new NativeFunction(flag_key_ptr, 'void', ['int', 'pointer', 'int']);
    const flag_len = 100;
    const flag = Memory.alloc(flag_len);

    flag_key(key, flag, flag_len);

    const flag_value = flag.readUtf8String();
    return flag_value;
  },
  watchcurl: () => {
    const curl_ptr = Process.mainModule.base.add(0x00001d2f);

    Interceptor.attach(curl_ptr, {
      onEnter(args) {
        send(`curl->() arg0="${args[0].readUtf8String()}" arg1=${args[1].readUtf8String()}`);
        this.response = args[2];
      },
      onLeave(retval) {
        send(`curl<-() arg3="${this.response.readUtf8String()}"`);
      }
    });
  },
  usecurl: (key: number) => {
    const curl_ptr = Process.mainModule.base.add(0x00001d2f);

    const curl = new NativeFunction(curl_ptr, 'void', ['pointer', 'pointer', 'pointer']);
    const response = Memory.alloc(100);

    const url = Memory.allocUtf8String("http://frown-service/");
    const key_ptr = Memory.allocUtf8String(key.toString());

    curl(url, key_ptr, response);

    return response.readUtf8String();
  },
  sendkey: (key: number) => {
    return new Promise((resolve, reject) => {
      const opts: http.RequestOptions = {
        hostname: 'frown-service',
        port: 80,
        path: '/',
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'content-length': key.toString().length
        }
      };

      const req = http.request(opts, (res) => {
        let body = '';

        res.on('data', (chunk) => {
          body += chunk;
        });

        res.on('end', () => {
          resolve(body);
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.write(key);
      req.end();
    });
  },
  exec: (c: string) => {
    const popen_ptr = Module.getExportByName(null, "popen");
    const fgets_ptr = Module.getExportByName(null, "fgets");
    const pclose_ptr = Module.getExportByName(null, "pclose");

    const popen = new NativeFunction(popen_ptr, 'pointer', ['pointer', 'pointer']);
    const fgets = new NativeFunction(fgets_ptr, 'pointer', ['pointer', 'int', 'pointer']);
    const pclose = new NativeFunction(pclose_ptr, 'int', ['pointer']);

    const command = Memory.allocUtf8String(c);
    const mode = Memory.allocUtf8String("r");
    const output_size = Process.pointerSize * 80;
    const output = Memory.alloc(output_size);

    const pipe = popen(command, mode);
    fgets(output, output_size, pipe);
    pclose(pipe);

    return output.readUtf8String();
  }
};
