tcppwn
===========

Python tool to attack integrity of TCP communications.<br/>

Copyright (C) 2019  Neetx

tcppwn is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

tcppwn is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

### CONTACTS:
[Neetx](mailto:neetx@protonmail.com)

---

### Explanation

tcppwn attacks tcp communication between two targets by IP addresses and destination PORT.

A <-----------> B

You need A ip address, B ip address and B or A port used to communicate. Usually it's more simple to use service open port like 80 or some others (if the victim is talking to a webserver, for example).

Then tcppwn does a simple Man In The Middle attack.

A <---> M <---> B

The packets manipulation is done by searching an ASCII sequence in the payloads, then it will be replaced with a new string.
Sequence number, ACK number, length and checksum are manipulated to perform a stealth and successful attack.

COMING SOON: More explanations.

### Setup:

LINUX SUPPORT ONLY.

```
git clone https://github.com/Neetx/tcppwn
apt install python-nfqueue
cd tcppwn
pip install -r requirements.txt
```

### Usage:
```
chmod +x tcppwn.py
sudo ./tcppwn.py <interface> <victimIP> <gatewayIP> <port> <stringtofind> <stringtoinject>
```

For example:
```
chmod +x tcppwn.py
sudo ./tcppwn.py wlan0 192.168.0.2 192.168.0.3 80 FINDME INJECTME
```

### Work in progress:

- Support the searching and injecting of hexadecimal sequence.
- Refactoring
- Bug fix