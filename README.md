# Percer

**Percer** is a Portable Executable (PE) file format dissection utility which I use to quickly get information about a PE file.
```
C:\>python percer.py --help
usage: percer.py [-h] [-a] [-e] [-i] [-s] [-c] PE

positional arguments:
  PE

options:
  -h, --help          show this help message and exit
  -a, --all           Show all info
  -e, --exports       List exports
  -i, --imports       List imports
  -s, --sections      List sections
  -c, --certificates  Get certificates information

Example (no options): python percer.py C:\Windows\System32\kernel32.dll
```

## Installation
Run the following commands to install Percer
```
git clone https://github.com/lem0nSec/Percer.git
cd Percer
pip install .
```

## Tool Example Usage 

![](pics/percer_1.png)

## Lib Example Usage
![](pics/percer_2.png)
