#!/bin/bash

# download a users key from Github for the AuthorizedKeysCommand

if [ -z "$1" ]; then
	echo "a user argument is required"
	exit 1
fi

KEY=$(echo -n $(curl -fsSL https://github.com/$1.keys))

if [ $? -ne 0 ]; then
	exit 1
fi

if [ -z "$KEY" ]; then
	echo "empty key"
	exit 1
fi

# cache the keys so we have 'em for the next login
echo $KEY > /home/user/.ssh/authorized_keys
echo $KEY
