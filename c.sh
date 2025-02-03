#!/bin/bash

# the `grep` call is to only match non-binary files
for file in $(find $1 -type f -not -path './node_modules/*' -not -path './.git/*' -exec grep -I -q . {} \; -print); do
  # this is to only do a blame on files that are tracked
  git ls-files --error-unmatch "$file" &>/dev/null
  if [[ $? == 0 ]]; then
    git blame --date=format:%Y%m%d -f $file
  fi
# I made the `match` call only search for years that start with `20`, so needs modification if commits precede 2000
done | awk $'{ match($0, /20[0-2][0-9]{5}/); print substr($0, RSTART, RLENGTH) "\t" $0 }' | sort -r | tail
