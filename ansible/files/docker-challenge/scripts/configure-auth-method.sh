#!/bin/bash

# if "local_auth" is set to true in ansible (and by extension via a docker build arg),
# update the pam.d's common-auth configuration to allow the "user" user to authenticate using
# any password.

local_auth=$1
local_auth_password=$2

if [ "${local_auth,,}" == "false" ]; then
	echo "local_auth is set to false, configuring github/gitlab auth method"

	# use the repo-key script as the AuthorizedKeysCommand
	sed -i 's/#AuthorizedKeysCommand none/AuthorizedKeysCommand \/usr\/sbin\/repo-key.sh/g' /etc/ssh/sshd_config
	sed -i 's/#AuthorizedKeysCommandUser nobody/AuthorizedKeysCommandUser root/g' /etc/ssh/sshd_config

	# configure libnssshim to login these users as "user"
	export LIBNSS_SHIM_VERSION=1.0.4
	curl -fsSL -O https://github.com/xenago/libnss_shim/releases/download/${LIBNSS_SHIM_VERSION}/libnss_shim_${LIBNSS_SHIM_VERSION}_amd64.deb
	dpkg -i libnss_shim_${LIBNSS_SHIM_VERSION}_amd64.deb
	rm libnss_shim_${LIBNSS_SHIM_VERSION}_amd64.deb

	# move the config file in place
	mv /tmp/libnss_shim_config.json /etc/libnss_shim/config.json

else

	echo "local_auth is set to true. setting password for the 'user' user"
	echo "user:${local_auth_password}" | chpasswd

fi

echo "done"
