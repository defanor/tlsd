#!/bin/sed -rf

s/^[^:]+: Initializing$//
T err
n
s/^[^:]+: Attempting to bind: [^ ,]+, port [0-9]+$//
T err
n
s/^[^:]+: Listening on [^ ,]+, port ([0-9]+)$/\1/
T err
q 0
: err
Q 1
