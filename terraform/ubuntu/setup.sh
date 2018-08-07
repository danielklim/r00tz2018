#!/bin/bash

apt-get -qq update

apt-get -qq install -y nginx php-fpm php-mysql mysql-server-5.7 vim php7.2-dom php7.2-gd php7.2-simplexml

# UPDATE mysql.user SET authentication_string=PASSWORD('1q2w3e4r') WHERE User='root';
# SET PASSWORD FOR 'root'@'localhost' = PASSWORD('1q2w3e4r');
mysql -u root <<-EOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '1q2w3e4r';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.db WHERE Db='test' OR Db='test_%';
FLUSH PRIVILEGES;

CREATE DATABASE drupal8 CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER drupal8@localhost IDENTIFIED BY '1q2w3e4r';
GRANT ALL ON drupal8.* TO 'drupal8'@'localhost' IDENTIFIED BY '1q2w3e4r';
FLUSH PRIVILEGES;
EOF

SRCDIR=/home/ubuntu
WWWDIR=/var/www/html
DRUPALTAR=drupal-pewpewkittens.tar.gz
DRUPALSQL=drupal-pewpewkittens.sql

# cd /home/ubuntu
cp $SRCDIR/nginx.conf /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default -rf

cp $SRCDIR/xrdp.ini /etc/xrdp/

cp $SRCDIR/$DRUPALTAR $WWWDIR/
tar -xf $WWWDIR/$DRUPALTAR -C $WWWDIR
sudo chown www-data:www-data -R $WWWDIR

mysql -u root drupal8 < $SRCDIR/$DRUPALSQL

# cd /var/www/html
# wget https://ftp.drupal.org/files/projects/drupal-8.5.0.tar.gz
# tar -xvf drupal-8.5.0.tar.gz
# mv drupal-8.5.0 drupal

(echo "1q2w3e4r"; echo "1q2w3e4r") | sudo passwd ubuntu
######

# apt install xfce4 xfce4-goodies tightvncserver 
# apt purge ubuntu-desktop gnome-panel gnome-settings-daemon metacity nautilus gnome-terminal xfce4 xfce4 xfce4-goodies tightvncserver 

apt-get -qq install -y ubuntu-gnome-desktop xrdp

# (echo "1q2w3e4r") | vncpasswd -f > ~/.vnc/passwd
# chmod 600 ~/.vnc/passwd

# cp xstartup,,,

https://www.hiroom2.com/2018/04/29/ubuntu-1804-xrdp-gnome-en/
cat <<EOF > ~/.xsessionrc
export GNOME_SHELL_SESSION_MODE=ubuntu
export XDG_CURRENT_DESKTOP=ubuntu:GNOME
export XDG_DATA_DIRS=${D}
export XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg
EOF

######
DEBIAN_FRONTEND=noninteractive apt-get -yq install wireshark tshark

cd /home/ubuntu
screen -dmS test
screen -S test -X stuff "tcpdump \"net 10.0.0.0/26\" -w traffic.pcap\n"

######
systemctl restart php7.2-fpm
systemctl restart nginx
systemctl restart xrdp
