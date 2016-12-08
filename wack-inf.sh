#!/bin/sh
until eval "./wack.sh level5"; do
	echo "Server 'myserver' crashed with exit code $?.  Respawning.." >&2
	sleep 1
done
