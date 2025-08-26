# arkanod
Any AMR or Modbus inquiries? Feel free to contact me at wishnu@pahlevi.id!

Poll EVC (Electronic Volume Corrector) data and archive log periodically using the 0-based address MODBUS protocol.

License:
    MIT License

    Copyright (c) 2024-2025 Wishnu Adhi Pahlevi <wishnu@pahlevi.id>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the “Software”), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

Tested in macOS Sequoia 15.5 and Debian GNU/Linux 12 (should be no issue in any other available Linux distros).
A more detailed explanation about how to use this software can be obtained by sending me an email.

## Prerequisites
- Python 3.11+
- Python mysqlclient library
- Follow the steps in https://pypi.org/project/mysqlclient/ to install the Python mysqlclient library first (omit the "pip install..")

## Install Steps
1. **Clone the repository**
```bash
mkdir /opt/arkanos
cd /opt/arkanos
git clone https://github.com/wishnu88/arkanod.git
cd arkanod
```
2. **Install dependencies and database tables**  
```bash
pip3 install -r requirements.txt
./main.py --create-tables
```
3. **Install systemd script (Debian/Ubuntu only)**  
```bash
cp init-scripts/systemd/arkanod.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable arkanod.service
```

More about the author:
- APNIC: WAP1-AP
- One of the founders of CyberPlus (PT Cyberplus Media Pratama - https://www.cyberplus.net.id/ - AS38771), an Internet Service Provider and IT System Integrator based in Bekasi, Indonesia since 2005.
- Part-time CTO of CyberPlus.
- Full-time Dad of ARP, RDP, NTP.
- Former IT Senior Manager of a shipping company in Indonesia.
- Former ICT Manager of a natural gas trader company.