#!/bin/bash
# install_vpn.sh
#  automatically install and configure a VPN -- IKEv2 over IPsec
#  using strongswan and iptables
# Author:  Lucas E Morales <lucas@lucasem.com>
#
# tested on Ubuntu 16.04 and arch 2018-07
#
# huge thanks to Namo's tutorial:
#   https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-16-04
#

set -e

if test "$(whoami)" != "root"
then echo "Sorry, you are not root." && exit 1
fi


# query user for variables
echo -n "Hostname: "
read hostname
echo -n "VPN Username: "
read user
echo -n "Password (must not contain \"): "
read -s pass
echo
echo "You may add more users at a later time by editing ~/vpn/ipsec.secrets"
echo

mkdir -p ~/vpn && cd ~/vpn


###########################
##### PREPARE SCRIPTS #####
###########################

echo "Preparing scripts and other files..."

cat > gen_certs.sh <<EOF
#!/bin/bash
rm vpn-server-cert.pem vpn-server-key.pem
ipsec pki --gen --type rsa --size 4096 --outform pem > server-root-key.pem
chmod 600 server-root-key.pem
ipsec pki --self --ca --lifetime 3650 \
  --in server-root-key.pem \
  --type rsa --dn "C=US, O=$hostname, CN=$hostname VPN Certificate" \
  --outform pem > server-root-ca.pem
ipsec pki --gen --type rsa --size 4096 --outform pem > vpn-server-key.pem
ipsec pki --pub --in vpn-server-key.pem \
  --type rsa | ipsec pki --issue --lifetime 1825 \
  --cacert server-root-ca.pem \
  --cakey server-root-key.pem \
  --dn "C=US, O=$hostname, CN=$hostname" \
  --san $hostname \
  --flag serverAuth --flag ikeIntermediate \
  --outform pem > vpn-server-cert.pem
mv vpn-server-cert.pem /etc/ipsec.d/certs/vpn-server-cert.pem
mv vpn-server-key.pem /etc/ipsec.d/private/vpn-server-key.pem
ln -s /etc/ipsec.d/certs/vpn-server-cert.pem vpn-server-cert.pem
ln -s /etc/ipsec.d/private/vpn-server-key.pem vpn-server-key.pem
chown root:root /etc/ipsec.d/private/vpn-server-key.pem
chmod 600 /etc/ipsec.d/private/vpn-server-key.pem
EOF
chmod +x gen_certs.sh

cat > reset_iptables.sh <<EOF
#!/bin/bash
if command -v ufw &>/dev/null
then ufw disable &>/dev/null
fi

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -Z
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.10.10.10/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.10.10.10/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.10/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.10/24 -o eth0 -j MASQUERADE
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.10/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP

if command -v netfliter-persistent &>/dev/null
then (netfilter-persistent save && netfilter-persistent reload) &>/dev/null
else (iptables-save > /etc/iptables/iptables.rules && iptables-restore </etc/iptables/iptables.rules)
fi
EOF
chmod +x reset_iptables.sh

cat > ipsec.conf <<EOF
# ipsec.conf - strongSwan IPsec configuration file
config setup
  charondebug="ike 1, knl 1, cfg 0"
  uniqueids=no
conn ikev2-vpn
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  ike=aes256-sha1-modp1024,3des-sha1-modp1024!
  esp=aes256-sha1,3des-sha1!
  dpdaction=clear
  dpddelay=300s
  rekey=no
  left=%any
  leftid=@$hostname
  leftcert=/etc/ipsec.d/certs/vpn-server-cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  rightsourceip=10.10.10.0/24
  rightdns=1.1.1.1,8.8.8.8,208.67.222.222
  rightsendcert=never
  eap_identity=%identity
EOF

cat > ipsec.secrets <<EOF
$hostname : RSA "/etc/ipsec.d/private/vpn-server-key.pem"
$user %any : EAP "$pass"
EOF

cat > 17-vpn.conf <<EOF
# VPN sysctl configuration
# Enable packet forwarding for IPv4
net.ipv4.ip_forward=1
# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
# Disable Path MTU discovery to prevent packet fragmentation problems
net.ipv4.ip_no_pmtu_disc = 1
EOF


################################
##### INSTALL DEPENDENCIES #####
################################

echo "Installing dependencies..."
sysinfo=$(uname -a |tr '[:upper:]' '[:lower:]')
if [[ "$sysinfo" =~ ubuntu ]]
then
  echo "    ..on Ubuntu, this consists of: {strongswan strongswan-plugin-eap-mschapv2 iptables-persistent}"
  apt-get install strongswan strongswan-plugin-eap-mschapv2 iptables-persistent &>/dev/null
elif [[ "$sysinfo" =~ arch ]]
then
  echo "    ..on Archlinux, this consists of: {strongswan(AUR), iptables}"
  if ! pacman -Qi strongswan &>/dev/null
  then
    echo "    please install strongswan using your preferred AUR installation method."
    exit 1
  elif pacman -Qi iptables &>/dev/null
  then :
  else pacman -S iptables &>/dev/null
  fi
  (systemctl start iptables ; systemctl enable iptables) &>/dev/null
  (systemctl start strongswan ; systemctl enable strongswan) &>/dev/null
else echo "WARNING: Unknown OS (not ubuntu or archlinux). Ensure strongswan and iptables are installed."
fi


##########################
##### GENERATE CERTS #####
##########################

echo "Generating certificates..."
./gen_certs.sh


###########################
##### CONFIGURE IPSEC #####
###########################

echo "Configuring IPsec..."
mv ipsec.conf /etc/ipsec.conf
mv ipsec.secrets /etc/ipsec.secrets
ln -s /etc/ipsec.conf ipsec.conf
ln -s /etc/ipsec.secrets ipsec.secrets


##############################
##### CONFIGURE IPTABLES #####
##############################

echo "Configuring iptables..."
./reset_iptables.sh


############################
##### CONFIGURE KERNEL #####
############################

echo "Configuring kernel networking parameters..."
if [ -d /etc/sysctl.d ]
then
  mv 17-vpn.conf /etc/sysctl.d/17-vpn.conf
  ln -s /etc/sysctl.d/17-vpn.conf 17-vpn.conf
elif [ -f /etc/sysctl.conf ]
then
  cat <(echo ; echo) 17-vpn.conf >> /etc/sysctl.conf
  rm 17-vpn.conf
else
  echo "could not locate sysctl configuration!"
  exit 1
fi
if command -v sysctl &>/dev/null
then sysctl --system &>/dev/null
else "NOTE: reboot may be necessary, could not live-reload kernel params."
fi


#########################
##### RESTART IPSEC #####
#########################

echo "Restarting IPsec..."
set +e
ipsec restart &>/dev/null
set -e


####################
##### COMPLETE #####
####################

cat <<EOF

INSTALL COMPLETE.
Please edit and re-execute reset_iptables.sh if appropriate.

Distribute ~/vpn/server-root-ca.pem to your clients,
ensure they enable trust for IPsec with that certificate.
EOF
