#!/bin/bash

set -e

export LD_LIBRARY_PATH=/usr/local/lib

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 (curl|pyclient) [arguments...]"
  exit 1
fi

command="$1"
shift # Remove the command from the argument list

case "$command" in
  shell)
    bash "$@"
    ;;
  curl)
    curl "$@"
    ;;
  pyclient)
    /code/venv/bin/python pyclient.py "$@"
    ;;
  *)
    echo "Unknown command: $command"
    exit 1
    ;;
esac
