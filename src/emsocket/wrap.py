#!/usr/bin/env python3

# Emscripten's linker doesn't support --wrap, so instead this script replaces
# all relevant #include directives (see TO_WRAP) with an include of <emsocket.h>.
# This ensure the emsocket_* functions will be used.
#
# Usage:
#   ./wrap.py <path_to_source_tree_to_modify>
#

TO_WRAP = [
  'sys/socket.h',
  'sys/select.h',
  'sys/epoll.h',
  'poll.h',
  'netdb.h',
  'unistd.h',
  'fcntl.h',
  'sys/ioctl.h',
]

import sys
import os
import re

def wrap(path):
  for entry in os.scandir(path):
    if entry.is_symlink():
      continue
    elif entry.is_dir(follow_symlinks=False):
      wrap(entry.path)
    elif entry.is_file(follow_symlinks=False):
      if entry.name.endswith(('.c', '.cpp', '.h')):
        wrap_file(entry.path)

include_line = re.compile(r'\#\s*include\s+<([^>]+)>(.*)', re.DOTALL)

def wrap_file(path):
  contents = open(path, 'rb').read().decode('utf8')
  lines = contents.splitlines(True)
  out = []
  changed = False
  for line in lines:
    m = include_line.match(line)
    if m and m.groups()[0].strip() in TO_WRAP:
      out.append('#include <emsocket.h>' + m.groups()[1])
      changed = True
    else:
      out.append(line)
  if changed:
    print("Edited " + path)
    with open(path, 'wb') as f:
      f.write(''.join(out).encode('utf8'))

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print("Usage: {} <path_to_source_tree_to_modify>".format(sys.argv[0]))
    sys.exit(1)
  path = sys.argv[1]
  wrap(path)
