#!/bin/bash

PASSWORD=cybercyber123

# "(echo \"${var.kali_user_password}\"; echo \"${var.kali_user_password}\") | sudo passwd ec2-user",
# "sudo sed -i '/PasswordAuthentication/d' /etc/ssh/sshd_config",
# "sudo bash -c \"echo \"PasswordAuthentication yes\" >> /etc/ssh/sshd_config\"",
# "sudo systemctl restart sshd"

apt-get -qq update

mkdir -p /root/.vnc
vncpasswd -f <<< $PASSWORD > "/root/.vnc/passwd"
chmod 600 ~/.vnc/passwd
vncserver -geometry 1600x1200

# DEBIAN_FRONTEND=noninteractive apt-get -yq install xrdp

# SRCDIR=/root

# cp $SRCDIR/xrdp.ini /etc/xrdp/
# systemctl enable xrdp
# systemctl start xrdp

## drupwn
# cd ~
# git clone https://github.com/immunIT/drupwn.git
# cd drupwn
# apt-get -qq install -y python3-pip
# pip3 install -r requirements.txt

cd ~
wget https://www.exploit-db.com/download/44449.rb
