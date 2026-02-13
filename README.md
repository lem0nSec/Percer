# Percer

**Percer** is a Portable Executable (PE) file format dissection utility/library which I use to quickly get information about a PE file both locally and from VirusTotal.
```
C:\>percer --help
usage: percer <PE file> [-h] (-F FILE | -H HASH) [-a] [-e] [-i] [-s] [-c] [-q]

options:
  -h, --help            show this help message and exit
  -F FILE, --file FILE  Target file
  -H HASH, --hash HASH  Target hash (VirusTotal Search requires VT_API_KEY)
  -a, --all             Show all info
  -e, --exports         List exports
  -i, --imports         List imports
  -s, --sections        List sections
  -c, --certificates    Get certificates information
  -q, --quiet           Do not print the banner
```

## Installation
Run the following commands to install Percer
```
git clone https://github.com/lem0nSec/Percer.git
cd Percer
pip3 install .
```

## Tool Example Usage 

![](pics/percer_1.png)

## Lib Example Usage
![](pics/percer_2.png)
