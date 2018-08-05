# Introduction

In this workshop you will learn about both the offensive and defensive sides of cyber security. Using open source tools, you will first gain access to (i.e. hack) a remote host (i.e. computer), then swap hats and examine the attack from the perspective of a network defender. The workshop is organized into 2 main parts. First, there is the offensive side:

1. [Scan using `nmap`](#scanning)
2. [Enumerate using `drupwn`](#enumerate)
3. [Exploit using `metasploit`](#exploit)

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

OS | SSH | Remote Desktop
------------ | ------------ | -------------
Linux | ssh (built-in) | [rdesktop](http://www.rdesktop.org/)
Windows | [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10) or [Bitvise SSH Client](https://www.bitvise.com/ssh-client) | Remote Desktop (built-in)
ChromeOS | [Secure Shell](https://chrome.google.com/webstore/detail/secure-shell/pnhechapfaindjhompbnflcldabbghjo) | [Chrome RDP](https://chrome.google.com/webstore/detail/chrome-rdp/cbkkbcmdlboombapidmoeolnmdacpkch)
OSX | ssh (built-in) | [CoRD](http://cord.sourceforge.net/)

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

First we need to figure out what is running on your target / what it even is. Is it someone's personal Macbook? A Linux based webserver in some server farm? A Windows server handling corporate email? A SCADA system controlling uranium enriching machines? Each of these will look very different and give rise to different attack vectors.

Nmap is a tool used for network discovery and scanning. In this case, we already know the address of our target so we will use the tool to see what is going on with the target from a network perspective. At its most basic, nmap lets us see what ports are open on the target system. 

```bash
nmap [target internal IP] -A -p20-450,3389
```

Ok, we see that ports 80, and 3389 are open. These ports are commonly associated with HTTP and RDP. On our target system there are one or more vulnerable services on each port. We will investigate each in turn.

## What's our goal?

Let's first see what our ultimate goal is. Remote desktop (RDP) is a service used by Windows based machines to provide GUI based interactivity over networks. The machine providing the connection typically listens on port 3389 for incoming connections, which is why we suspect (though don't know for sure yet) this machine provides the service. From your physical machine, try connecting to the machine via RDP. On Windows based hosts, type "remote desktop" into the search / run bar and fill in the blanks. For CLI, try something like:

```bash
rdesktop [target external IP]
```

You should see a login screen. However, we are stopped at the gates because we don't have credentials for the box. At this point, we know there is something potentially interesting here but we don't know how interesting, or how to get that interesting stuff. For now, our goal is to answer these questions. We will do so by exploiting vulnerabilities in the services hosted by this box.

# Enumerate

# Exploit

# Surveil

# Protect

# Respond

