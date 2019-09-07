# Client tools

This directory contains code for clients connecting to the socket launcher server,
and code to run the tests of socket launcher performance.

The C tools create a configurable number of clients which connect simultaneously,
which then send TCP packets at as high of a rate as possible, verifying
that the responses match the requested string.

The `xfer_echo_client` performs the same task, but additionally will send a
command containing the string "xfer" -- a signal to Socket Launcher that
it should initiate the transfer process.
