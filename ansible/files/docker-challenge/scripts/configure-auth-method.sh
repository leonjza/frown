#!/bin/bash

# if "allow_any_password" is set to true in ansible (and by extension via a docker build arg),
# update the pam.d's common-auth configuration to allow the "user" user to authenticate using
# any password.

if [ "${1,,}" == "false" ]; then
	echo "allow_any_password is set to false, configuring github/gitlab auth method"

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
	echo "allow_any_password is set to true. updating pam to accept any password for the 'user' user"

	# add a pam control
	sed -i '/^auth[[:space:]]\+\[success=1[[:space:]]\+default=ignore][[:space:]]\+pam_unix\.so[[:space:]]\+nullok$/{
	s//auth    [success=2 default=ignore]      pam_unix.so nullok\nauth    [success=1 default=ignore]      pam_succeed_if.so user = user/
	}' /etc/pam.d/common-auth
fi

echo "done"
