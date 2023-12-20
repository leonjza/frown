#!/bin/bash

# run tetris for 8 hours maximum. this will help clean up stale containers
# that lost it's SSH connection while also not being too frustrating.

/usr/bin/timeout \
	`# if you can see this, this is not a memory corruption challenge` \
	`# the command you are seeing now is simply challenge plumbing` \
	--foreground \
	--preserve-status 8h \
	/usr/local/bin/tetris
