FROM debian:bookworm-slim as tetris

RUN apt update && apt install -y --no-install-recommends \
	ca-certificates curl git cmake make g++ libncurses-dev xz-utils

# build https://github.com/Holixus/tty-tetris-v2.git
ADD tty-tetris-v2/ /usr/src/tty-tetris-v2/
RUN cd /usr/src/tty-tetris-v2 && \
	cmake . && \
	make && \ 
	ls -lah

# grab and extract a frida-gadget
ENV FRIDA_VERSION=16.1.8
RUN cd /usr/local/lib/ && \
	curl -O -fsSL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-linux-x86_64.so.xz && \
	unxz frida-gadget-${FRIDA_VERSION}-linux-x86_64.so.xz && \
	mv frida-gadget-${FRIDA_VERSION}-linux-x86_64.so frida-gadget.so

#---

FROM debian:bookworm-slim

COPY --from=tetris /usr/src/tty-tetris-v2/tty-tetris /usr/local/bin/tetris
COPY --from=tetris /usr/local/lib/frida-gadget.so /usr/local/lib/frida-gadget.so
COPY frida/frida-gadget.config /usr/local/lib/frida-gadget.config

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y --no-install-recommends \
	openssh-server curl ca-certificates \
	&& apt-get autoremove -y && \
	apt-get clean

# create the default user we will use
RUN useradd --create-home user && \
	mkdir /home/user/.ssh && \
	touch /home/user/.ssh/authorized_keys && \
	chmod 600 /home/user/.ssh/authorized_keys && \
	chown -R user:user /home/user/.ssh && \
	touch /home/user/.hushlogin && \
	# 'fix' ssh
	mkdir /var/run/sshd

# We want to allow anyone to login. But in a small attempt to prevent
# obvious abuse, (and as a bit of an excuse to play with it), we'll
# limit SSH logins to valid github accounts. That means when you SSH
# in with login set to your Github username, presenting your Github
# private key should drop you in a shell as user.

# To do that, we configure sshd's AuthorizedKeysCommand to a script that
# will download the keys a user has configured on Github and use those
# for public key authentication. Next, we use [1] libnss_shim to "fake"
# the user by returning the details of the already configured user 'user'.
#
# [1] https://github.com/xenago/libnss_shim

COPY scripts/github-key.sh /usr/sbin/github-key.sh
RUN sed -i 's/#AuthorizedKeysCommand none/AuthorizedKeysCommand \/usr\/sbin\/github-key.sh/g' /etc/ssh/sshd_config && \
	sed -i 's/#AuthorizedKeysCommandUser nobody/AuthorizedKeysCommandUser root/g' /etc/ssh/sshd_config

ENV LIBNSS_SHIM_VERSION=1.0.4
RUN curl -fsSL -O https://github.com/xenago/libnss_shim/releases/download/${LIBNSS_SHIM_VERSION}/libnss_shim_${LIBNSS_SHIM_VERSION}_amd64.deb && \
	dpkg -i libnss_shim_${LIBNSS_SHIM_VERSION}_amd64.deb && \
	rm libnss_shim_${LIBNSS_SHIM_VERSION}_amd64.deb
COPY libnss_shim/config.json /etc/libnss_shim/config.json
COPY scripts/start-tetris.sh /start-tetris.sh

COPY docker-entrypoint.sh /docker-entrypoint.sh

EXPOSE 22

CMD [ "/docker-entrypoint.sh" ]
