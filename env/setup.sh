#!/bin/bash

sudo add-apt-repository -y ppa:apt-fast/stable
sudo add-apt-repository -y ppa:ultradvorka/ppa
sudo add-apt-repository -y ppa:saiarcot895/myppa
sudo add-apt-repository -y ppa:certbot/certbot
sudo apt -y install apt-fast

sudo cp completions/bash/apt-fast /etc/bash_completion.d/
sudo chown root:root /etc/bash_completion.d/apt-fast
sudo . /etc/bash_completion

#### bash history  ####
sudo apt-fast update | sudo apt-fast install hstr
hstr --show-configuration >> ~/.bashrc && . ~/.bashrc


### is.sh  ####
# https://github.com/qzb/is.sh

sudo sh -c 'cd /usr/local/bin && wget raw.githubusercontent.com/qzb/is.sh/latest/is.sh -O is && chmod +x is'


# Allow apt to install system updates automatically every day.
sudo cat > /etc/apt/apt.conf.d/02periodic <<EOF;
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

#curl https://raw.githubusercontent.com/carlstrand/mailinabox/master/setup/bootstrap.sh | sudo bash
#curl https://raw.githubusercontent.com/carlstrand/shellstuff/master/env/setup.sh | sudo bash
