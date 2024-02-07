![Header](images/header.png)

# Introduction

This repository provides a simple daemon and CLI tool to execute and manage background processes.

# Quickstart

First, you have to start the daemon for your current user. The daemon will handle the start, kill and status of all processes.

```bash
pm daemon
```
The daemon will create the socket file `/tmp/pm-<user>.sock` that is used by all `pm` calls to connect.

While the daemon is active you can command it to start and kill processes or to retrieve the status.
```bash
# Start process in background
pm run -- sleep 15
# The argument '--' is only necessary if your command takes arguments with '-' prefix
# That's the case because else clap parser will try to use it and fail.

# Get status of active processes
pm status

# Kill any active process
pm kill <PID1> <PID2> ...
```
