import pathlib

import frida

def on_message(message, data):
    print(message)

agent_path = pathlib.Path(__file__).parent / 'frida' / '_agent.js'
remote = 'localhost:27042'

device_manager = frida.get_device_manager()
session = device_manager.add_remote_device(remote).attach("Gadget")

with open(agent_path, 'r') as f:
	agent = ''.join(f.readlines())

script = session.create_script(agent)

script.on('message', on_message)
script.load()

api = script.exports_sync

# get the binay locally to reverse
# with open('tetris', 'wb') as f:
# 	f.write(bytes(api.getbin()['data']))

# dont dlclose the libttyris library
# api.blockdlclose()

# brute the key passed to get_flag
for x in range(0, 2000):
	flag = api.getflag(x)
	if '*' not in flag:
		print(flag)
		# break

# input('[enter] to exit ...')
