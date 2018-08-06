#!/bin/bash

apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -yq install xrdp

## drupwn
# cd ~
# git clone https://github.com/immunIT/drupwn.git
# cd drupwn
# apt-get -qq install -y python3-pip
# pip3 install -r requirements.txt

cd ~
wget https://www.exploit-db.com/download/44449.rb
