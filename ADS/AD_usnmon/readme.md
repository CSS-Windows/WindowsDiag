# UsnMon.exe

## Description 
Command line tool, needs to be executed in a administrator elevated command prompt.
When running it displays file and folder changes from the NTFS Journal for the specified drive.

## Note
The tools is useful in conjunction with DFSR, to verify if the USN CLOSE statement is appearing in customer environments. 
The DFSR NTFS Journal consumer reacts only on changes with the CLOSE statement. If these are not committed in time, it can cause a DFSR replication delay.
The tool works read only, only presenting object change information, but no content.

## Usage

usnmon x: [-verbose]

Normal Mode example:
d:\CorpInstall\Tools\utest.txt FILE_CREATE
d:\CorpInstall\Tools\utest.txt DATA_EXTEND FILE_CREATE
d:\CorpInstall\Tools\utest.txt DATA_EXTEND FILE_CREATE CLOSE

Verbose Mode example (with date, time, USN and FID):
Mon Dec 02 13:19:19 2019
 usn 0xc4ffe80 id 0x2460000000026be d:\CorpInstall\Tools\utest.txt DATA_EXTEND
Mon Dec 02 13:19:19 2019
 usn 0xc4ffed0 id 0x2460000000026be d:\CorpInstall\Tools\utest.txt DATA_EXTEND CLOSE

