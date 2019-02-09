#!/bin/bash

apt update 
apt install software-properties-common dialog

add-apt-repository -y ppa:apt-fast/stable
add-apt-repository -y ppa:ultradvorka/ppa
add-apt-repository -y ppa:saiarcot895/myppa
add-apt-repository -y ppa:certbot/certbot

apt install apt-fast

#cp completions/bash/apt-fast /etc/bash_completion.d/
#chown root:root /etc/bash_completion.d/apt-fast
#source /etc/bash_completion

#### bash history  ####
apt-fast update | apt-fast install hstr
hstr --show-configuration >> ~/.bashrc && . ~/.bashrc


### is.sh  ####
# https://github.com/qzb/is.sh

#sudo sh -c 'cd /usr/local/bin && wget raw.githubusercontent.com/qzb/is.sh/latest/is.sh -O is && chmod +x is'


# Allow apt to install system updates automatically every day.
cat > /etc/apt/apt.conf.d/02periodic <<EOF;
APT::Periodic::MaxAge "7";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "0";
EOF

if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    if ! grep -q "$1" /etc/apt/apt.conf.d/50unattended-upgrades; then
        sudo sed -i "/Allowed-Origins/a \
        \"$1\";" /etc/apt/apt.conf.d/50unattended-upgrades
    fi
fi



#source setup/packages-install.sh
#source setup/build-webmail.sh

#curl https://raw.githubusercontent.com/carlstrand/mailinabox/master/setup/packages-install.sh | sudo bash
#curl https://raw.githubusercontent.com/carlstrand/shellstuff/master/env/setup.sh | sudo bash


