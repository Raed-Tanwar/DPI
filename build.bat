@echo off
if not exist bin mkdir bin
javac -encoding UTF-8 -d bin src\main\java\com\dpi\types\*.java src\main\java\com\dpi\pcap\*.java src\main\java\com\dpi\parser\*.java src\main\java\com\dpi\extractor\*.java src\main\java\com\dpi\engine\*.java
echo Build successful.
