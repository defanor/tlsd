#!/bin/sh

# Assuming that tlsd and the plugin are installed, the key and
# certificate are already generated, placed into /etc/tls/, and are
# accessible to the tlsd group.
install tlsd-im{,-cmd,-reconnect}.sh /usr/local/bin/
useradd --system -G tlsd tlsd-im
gpasswd -a bitlbee tlsd-im
gpasswd -a $USER tlsd-im
mkdir -p /var/lib/tlsd-im/
chown tlsd-im:tlsd-im /var/lib/tlsd-im/
chmod g+w /var/lib/tlsd-im
install tlsd-im.service tlsd-im-reconnect.{service,timer} /etc/systemd/system/
systemctl enable tlsd-im.service tlsd-im-reconnect.timer
systemctl start tlsd-im.service tlsd-im-reconnect.timer
