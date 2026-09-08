#!/usr/bin/env bash
set -e
mkdir -p bin
javac -encoding UTF-8 -d bin $(find src/main/java -name '*.java')
echo "Build successful."
