#!/bin/sh
#

set -e

if [ -z "$1" ]
then
  echo "need a target ip"
  echo "Usage: $0 <target>"

  exit 1
fi

echo "targetting $1, will ask for sudo password"

ansible-playbook -i $1, playbook.yml -K
