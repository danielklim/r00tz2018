# Introduction

In this workshop you will be introduced to the basics of cyber security from the perspectives of both the attacker and the defender. Using open source tools, you will first gain access to (i.e. hack) a remote network. You will then swap hats and examine the attack from the perspective of a defender of said network. The workshop is organized into 2 main segments. First, there is the offensive side:

1. [Scan using `zenmap`](#scan)
2. [Enumerate using `nmap` and `drupwn`](#enumerate)
3. [Exploit an HTTP form vulnerability](#exploit-http)
4. [Pivot and exploit a buffer overflow RCE](#exploit-rce)

Once we have gained access to the system (i.e. won as the attacker), we will take a look at the attack from the view of a defender and consider how we could have / can mitigate similar attacks in the future. Specifically we will do the following:

1. [Surveil using `tcpdump` and `wireshark`](#surveil)
2. [Protect by reading security advisories](#protect)
3. [Respond by patching the system](#respond)

## Rules

1. Do not attack any hosts other than your assigned target. 
2. Do not attack the infrastructure.
3. Do not use the infrastructure for anything other than the prescribed activities. E.g., don't use workshop resources to browse social media, mine cryptocurrency, do your schoolwork, etc.
4. Do not use the offensive techniques or tools covered in this workshop against systems that you are unauthorized to attack / pentest. DOING SO IS A FEDERAL CRIME AND WILL CARRY SIGNIFICANT CRIMINAL PENALTIES. 

We are completely OK with you breaking stuff as you learn, so don't be afraid to try things not explicitly covered by the facilitators. However, violating the above intentionally or in a manner which is disruptive to other participants is grounds for immediate removal from the workshop.

# Setup

You may complete this workshop using one of the provided laptops or your own. At a minimum, you will need a system with an SSH client and a remote desktop client. Depending on what type of system you're on, the following programs will meet these requirements.

OS | SSH | VNC
------------ | ------------ | -------------
Linux | ssh | [vncviewer](http://tigervnc.org/doc/vncviewer.html)
Windows | ssh in [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10) or [Bitvise SSH Client](https://www.bitvise.com/ssh-client) | [VNC Viewer](https://www.realvnc.com/en/connect/download/viewer/)
OSX | ssh | [VNC Viewer](https://www.realvnc.com/en/connect/download/viewer/macos/)

Each workstation should have assigned to it a set of 4 IP addresses.

- You (external): machine you will be SSHing into to access your offensive tools
- You (internal): don't worry about this for now
- Target (external): host you will be attacking
- Target (internal): don't worry about this for now

If you are using your own hardware, just ask one of the facilitators for a set of IPs to work with.

When you are ready, SSH into your workstation using either (1) the provided private key, or (2) the password: cybercyber123

For GUI based SSH clients, just fill in the appropriate blanks. For command line clients (CLI), the syntax will look something like:

```bash
ssh ec2-user@[your external IP]
```

# Scan

Assume you are an attacker. You've landed in some strange network and you don't yet know what that network looks like. To understand the lay of the land, you need to scan this network.

For this task, we will use a tool called `zenmap`. `zenmap` is a GUI (graphical user interface) for a popular command-line network scanning tool called `nmap` (which we use later in this workshop). We use it here for 2 reasons: 1. it is a gentle intro into security tools for folks who are unfamiliar with the command line, and 2. it has a network topology view that is useful for complicated networks.

Start `zenmap` by clicking 'Applications' (top left of screen) and selecting 'Run program.' You will get a screen that looks like:

![zenmap0.png](/img/zenmap0.png){:class="img-responsive"}

In the space for 'target,' type `10.0.0.0/24`. This means that you will be scanning the network consisting of IP addresses between 10.0.0.1 and 10.0.0.254 (see [Wikipedia](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) for an explanation). The goal is to see which addresses actually have hosts (i.e. computers) attached to them. These are potential targets.

For 'profile,' select 'Ping scan.' This means you will be sending just a few packets to each possible IP address, just to see if there's anything there. `nmap` and `zenmap` have the ability to extensively interrogate hosts to gain a great deal of info but for now, that is unnecessary overkill, so instead we will just ping scan. When ready, click the scan button. After a few seconds, you should see something like:

![zenmap0.png](/img/zenmap1.png){:class="img-responsive"}

# Enumerate

Next, we need to figure out what is running on your target / what it even is. Is it someone's personal Macbook? A Linux based webserver in some server farm? A Windows server handling corporate email? A SCADA system controlling uranium enriching machines? Each of these will look very different and give rise to different attack vectors.

Nmap is a tool used for network discovery and scanning. In this case, we already know the address of our target so we will use the tool to see what is going on with the target from a network perspective. At its most basic, nmap lets us see what ports are open on the target system. 

```bash
nmap [target internal IP] -T5 -A -sS -p20-100,5900-5910
```

You will get output that looks similar to the following:

```
Starting Nmap 7.60 ( https://nmap.org ) at 2018-08-07 04:30 UTC
Nmap scan report for 10.0.0.110
Host is up (0.00043s latency).
Not shown: 89 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 cf:92:8c:0a:5c:54:44:cc:0b:47:f0:60:f3:1e:d4:ae (RSA)
|   256 75:a5:dc:f0:f8:14:20:8b:d7:06:e8:be:56:ff:f9:fc (ECDSA)
|_  256 72:8b:c1:81:06:ad:a6:9a:6e:07:ee:60:2b:f5:7e:92 (EdDSA)
80/tcp   open  http    nginx 1.14.0 (Ubuntu)
|_http-generator: Drupal 8 (https://www.drupal.org)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/
| /comment/reply/ /filter/tips/ /node/add/ /search/ /user/register/
| /user/password/ /user/login/ /user/logout/ /index.php/admin/
|_/index.php/comment/reply/
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Choose language | Drupal
|_Requested resource was /core/install.php
5901/tcp open  vnc     VNC (protocol 3.8)
| vnc-info:
|   Protocol version: 3.8
|   Security types:
|     VNC Authentication (2)
|     Tight (16)
|   Tight auth subtypes:
|_    STDV VNCAUTH_ (2)
MAC Address: 06:27:7E:21:CB:40 (Unknown)
Aggressive OS guesses: Linux 3.13 (96%), Linux 3.8 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.19 (92%), Linux 3.2 - 4.8 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ok, we see that ports 22, 80, and 3389 are open. These ports are commonly associated with SSH, HTTP and RDP. On our target system there are one or more vulnerable services on each port. We will investigate each in turn.

## What's our goal?

Let's first see what our ultimate goal is. Remote desktop (RDP) is a service used by Windows based machines to provide GUI based interactivity over networks. The machine providing the connection typically listens on port 3389 for incoming connections, which is why we suspect (though don't know for sure yet) this machine provides the service. From your physical machine, try connecting to the machine via RDP. On Windows based hosts, type "remote desktop" into the search / run bar and fill in the blanks. For CLI, try something like:

```bash
rdesktop [target external IP]
```

You should see a login screen. However, we are stopped at the gates because we don't have credentials for the box. At this point, we know there is something potentially interesting here but we don't know how interesting, or how to get that interesting stuff. For now, our goal is to answer these questions. We will do so by exploiting vulnerabilities in the services hosted by this box.

# Exploit-Http

# Exploit-RCE

# Surveil

# Protect

# Respond

# Notes
