#!/bin/bash

# download a users key from Github/Gitlab for the AuthorizedKeysCommand

if [ -z "$1" ]; then
	echo "a user argument is required"
	exit 1
fi

USER=$(echo "$1" | cut -d'@' -f1)
SERVICE=$(echo "$1" | cut -d'@' -f2)

if [ -z "$USER" ]; then
	echo "empty user"
	exit 1
fi

if [ -z "$SERVICE" ]; then
	echo "empty service"
	exit 1
fi

KEY=$(curl -fsSL https://$SERVICE.com/$USER.keys)

if [ $? -ne 0 ]; then
	echo "key curl failed"
	exit 1
fi

if [ -z "$KEY" ]; then
	echo "empty key"
	exit 1
fi

# cache the keys so we have 'em for the next login
echo $KEY > /home/user/.ssh/authorized_keys
echo $KEY
