import pathlib
import sys
from pprint import pprint

import frida


def on_message(message, data):
	if 'payload' in message:
	    print(message['payload'])

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

# allow for dynamic rpc_func(args) invocation
# example:
#	python -m solution exec ls
if len(sys.argv) > 1:
	func = getattr(api, sys.argv[1])
	args = ' '.join(sys.argv[2:])
	if (ret := func(args)):
		pprint(ret)

	input('[enter] to exit ...')
	sys.exit(0)

# get the binary locally to reverse
# with open('tetris', 'wb') as f:
# 	f.write(bytes(api.getfile(api.binpath())['data']))
# 	print('saved tetris binary locally')

# get the flag shared lib for lcal reversing
# with open('libttyris.so', 'wb') as f:
# 	f.write(bytes(api.getfile("/usr/lib/libttyris.so")['data']))
# 	print('saved libttyris')

# solve via node http
# for x in range(0, 40000):
# 	if 'flag' in (flag := api.sendkey(api.flagkey(x))):
# 		print(f'key: {x}, flag: {flag}')
# 		break

# solve via curl hook
for x in range(0, 40000):
	if 'INS' in (flag := api.usecurl(api.flagkey(x))):
		print(f'key: {x}, flag: {flag}')
		break
