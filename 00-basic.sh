#!/bin/bash

#BASIC
#Copyright (C) 2018-2019 James Moore

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

##################
# Mass  Security #
#     Script     #
##################

BRED="\033[1;31m"
BLUE="\033[0;34m"
GREEN="\033[0;32m"
ENDCOLOR="\033[0m"

# Hardening Variables
MEMORY_SHUFFLING=$(cat /proc/sys/kernel/randomize_va_space)
MEMORY_SHUFFLING_FILE=$(cat /etc/sysctl.conf | grep '^kernel.randomize_va_space')
SUID_DUMPABLE=$(cat /etc/sysctl.conf | grep '^fs.suid_dumpable')
KERNEL_EXEC=$(cat /etc/sysctl.conf | grep '^kernel.exec-shield')
IP_FORWARDING=$(cat /etc/sysctl.conf | grep '^net.ipv4.ip_forward')
PACKET_REDIRECTS_1=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.all.send_redirects')
PACKET_REDIRECTS_2=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.default.send_redirects')
ICMP_REDIRECT_1=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.all.accept_redirects')
ICMP_REDIRECT_2=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.default.accept_redirects')
MESSAGE_PROTECTION=$(cat /etc/sysctl.conf | grep '^net.ipv4.icmp_ignore_bogus_error_responses')
#BOOT_DIRECTORY=$(cat /etc/fstab | grep '^LABEL=/boot')

# Other Variables
UFW_STATUS=$(sudo ufw status | grep 'Status:')
GUEST_ACCOUNT=$(cat /etc/lightdm/lightdm.conf 2>/dev/null | grep "allow-guest")

# Service Variables
SSH=$(dpkg -l 2>/dev/null | grep "openssh-server" | tail -n 1 | awk '{print $1}')
APACHE=$(dpkg -l 2>/dev/null | grep "apache2" | tail -n 1 | awk '{print $1}')
VSFTP=$(dpkg -l 2>/dev/null | grep "vsftpd" | tail -n 1 | awk '{print $1}')
PUREFTPD=$(dpkg -l 2>/dev/null | grep "pure-ftpd" | tail -n 1 | awk '{print $1}')

echo -e $BRED"Root permissions are required to run this script."$ENDCOLOR
sudo echo ""
mkdir $PWD/backups
clear

echo -e $BLUE"Do you want to enable memory shuffling?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  if [ "$MEMORY_SHUFFLING" != "2" ]
  then
    sudo su -c "echo '2' > /proc/sys/kernel/randomize_va_space"
  fi
  if [ "$MEMORY_SHUFFLING_FILE" != "kernel.randomize_va_space" ]
  then
    echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$MEMORY_SHUFFLING_FILE" != "kernel.randomize_va_space = 2" ]
  then
    sudo sed -i 's/^kernel.randomize_va_space = ?/kernel.randomize_va_space = 2/g' /etc/sysctl.conf
  fi
fi

echo -e $BLUE"Do you want to enable firewall?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  if [ "$UFW_STATUS" != "Status: active" ]
  then
    sudo ufw enable
  fi
  sudo ufw logging on
  sudo ufw logging high
  OPEN_FW=$(sudo ufw status | grep -v "Status\|To\|---" | nl | tail -n1)
  if [ "$OPEN_FW" -ge '1' ]
  then
    echo -e $GREEN"Outputting open firewall ports to $PWD/open-fw.txt"$ENDCOLOR
    sudo ufw status > ./open-fw.txt
  fi
fi

echo -e $BLUE"Do you want to disable guest?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  if [ "$GUEST_ACCOUNT" != "allow-guest=false" ]
  then
    cp /etc/lightdm/lightdm.conf $PWD/backups/lightdm.conf.bak 2>/dev/null
    sudo sed -i 's/allow-guest=true/allow-guest=false/g' /etc/lightdm/lightdm.conf 2>/dev/null
    sudo /usr/lib/lightdm/lightdm-set-defaults -l false 2>/dev/null
  fi
fi

echo -e $BLUE"Do you want to set password policies?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  cp /etc/pam.d/common-password $PWD/backups/common-password.bak
  cp /etc/login.defs $PWD/backups/login.defs.bak
  sudo apt-get install -y libpam-pwquality 1>/dev/null
  sudo sed -i 's/^PASS_MAX_DAYS	*/PASS_MAX_DAYS	60/g' /etc/login.defs
  sudo sed -i 's/^PASS_MIN_DAYS	*/PASS_MIN_DAYS	14/g' /etc/login.defs
  echo "password sufficient pam_unix2.so use_authtok md5 shadow remember=10" | sudo tee -a /etc/pam.d/common-password > /dev/null
  sudo sed -i 's/password.*requisite.*pam_pwquality.so.*retry=3.*/password requisite pam_pwquality.so retry=3 ucredit=-1 dcredit=-1 ocredit=-1 minclass=2/g' /etc/pam.d/common-password
  sudo sed -i 's/^password [success=2 default=ignore] pam_unix.so obscure sha512/password [success=2 default=ignore] pam_unix.so obscure sha512 minlen=10/g' /etc/pam.d/common-password
fi

echo -e $BLUE"Do you want to list and save users?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  eval getent passwd {"$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)".."$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)"} > users.txt
fi

echo -e $BLUE"Do you want to enable misc hardening?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  echo 'hard nproc $(ps aux -L | cut --delimiter=" " --fields=1 | sort | uniq --count | sort --numeric-sort | tail --lines=1)' | sudo tee -a /etc/security/limits.conf > /dev/null
  echo 'hard core 0' | sudo tee -a /etc/security/limits.conf > /dev/null
  # if [ "$BOOT_DIRECTORY" != "^LABEL=/boot" ]
  # then
  #   echo "LABEL=/boot /boot ext2 defaults,ro 1 2" | sudo tee -a /etc/fstab > /dev/null
  # elif [ "$BOOT_DIRECTORY" != "^LABEL=/boot.*/boot.*ext2.*defaults,ro.*1.*2" ]
  # then
  #   sudo sed -i 's/^LABEL=/boot.*/LABEL=/boot /boot ext2 defaults,ro 1 2/g' /etc/fstab
  # fi
  if [ "$SUID_DUMPABLE" != "^fs.suid_dumpable" ]
  then
    echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$SUID_DUMPABLE" != "^fs.suid_dumpable = 0" ]
  then
    sudo sed -i 's/^fs.suid_dumpable = ?/fs.suid_dumpable = 0/g' /etc/sysctl.conf
  fi
  if [ "$KERNEL_EXEC" != "^kernel.exec-shield" ]
  then
    echo "kernel.exec-shield = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$KERNEL_EXEC" != "^kernel.exec-shield = 1" ]
  then
    sudo sed -i 's/^kernel.exec-shield = ?/kernel.exec-shield = 1/g'
  fi
  if [ "$IP_FORWARDING" != "^net.ipv4.ip_forward" ]
  then
    echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$IP_FORWARDING" != "^net.ipv4.ip_forward = 0" ]
  then
    sudo sed -i 's/^net.ipv4.ip_forward = ?/net.ipv4.ip_forward = 0/g' /etc/sysctl.conf
  fi
  if [ "$PACKET_REDIRECTS_1" != "^net.ipv4.conf.all.send_redirects" ]
  then
    echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$PACKET_REDIRECTS_1" != "^net.ipv4.conf.all.send_redirects = 0" ]
  then
    sudo sed -i 's/^net.ipv4.conf.all.send_redirects = ?/net.ipv4.conf.all.send_redirects = 0/g' /etc/sysctl.conf
  fi
  if [ "$PACKET_REDIRECTS_2" != "^net.ipv4.conf.default.send_redirects" ]
  then
    echo "net.ipv4.conf.default.send_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$PACKET_REDIRECTS_2" != "^net.ipv4.conf.default.send_redirects = 0" ]
  then
    sudo sed -i 's/^net.ipv4.conf.default.send_redirects = ?/net.ipv4.conf.default.send_redirects = 0/g' /etc/sysctl.conf
  fi
  if [ "$ICMP_REDIRECT_1" != "^net.ipv4.conf.all.accept_redirects" ]
  then
    echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$ICMP_REDIRECT_1" != "^net.ipv4.conf.all.accept_redirects = 0" ]
  then
    sudo sed -i 's/^net.ipv4.conf.all.accept_redirects = ?/net.ipv4.conf.all.accept_redirects = 0/g' /etc/sysctl.conf
  fi
  if [ "$ICMP_REDIRECT_2" != "^net.ipv4.conf.default.accept_redirects" ]
  then
    echo "net.ipv4.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$ICMP_REDIRECT_2" != "^net.ipv4.conf.default.accept_redirects = 0" ]
  then
    sudo sed -i 's/^net.ipv4.conf.default.accept_redirects = ?/net.ipv4.conf.default.accept_redirects = 0/g' /etc/sysctl.conf
  fi
  if [ "$MESSAGE_PROTECTION" != "^net.ipv4.icmp_ignore_bogus_error_responses" ]
  then
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [ "$ICMP_REDIRECT_2" != "^net.ipv4.icmp_ignore_bogus_error_responses = 0" ]
  then
    sudo sed -i 's/^net.ipv4.icmp_ignore_bogus_error_responses = ?/net.ipv4.icmp_ignore_bogus_error_responses = 0/g' /etc/sysctl.conf
  fi
fi

echo -e $BLUE"Do you want to remove hacking tools and games?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  cat games.txt | xargs sudo apt-get purge -y
  cat hacking-tools.txt | xargs sudo apt-get purge -y
fi

echo -e $BLUE"Do you want to list users with blank passwords?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  sudo awk -F: '$2 == "" {print $1, "has no password!" }' /etc/shadow > ./blank-passwords.txt
fi

echo -e $BLUE"Do you want to install and run ClamAV?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  sudo apt-get install -y clamav
  sudo freshclam
  sudo clamscan --max-filesize=3999M --max-scansize=3999M --exclude-dir=/sys/* -i -r /
fi

echo -e $BLUE"Do you want to list all cron tabs?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  echo -e "/etc/cron.d is: $(ls /etc/cron.d)\n" > $PWD/crons.txt
  echo -e "Daily crons: $(ls /etc/cron.daily)\n" > $PWD/crons.txt
  echo -e "Hourly crons: $(ls /etc/cron.hourly)\n" > $PWD/crons.txt
  echo -e "Weekly crons: $(ls /etc/cron.weekly)\n" > $PWD/crons.txt
  echo -e "Monthly crons: $(ls /etc/cron.monthly)\n" > $PWD/crons.txt
fi

# Securing Services
echo -e $BLUE"Is SSH needed?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  if [ "$SSH" = 'ii' ]
  then
    cp /etc/ssh/sshd_config $PWD/backups/sshd_config.bak
    tail -n -10 /etc/ssh/sshd_config > sshd_config
    mv sshd_config /etc/ssh/sshd_config
    sudo sed -i 's/.*Ciphers .*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*ClientAliveCountMax .*/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*ClientAliveInterval .*/ClientAliveInterval 900/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*HostbasedAuthentication .*/IgnoreRhosts no/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*IgnoreRhosts .*/IgnoreRhosts yes/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*MaxAuthTries .*/MaxAuthTries 5/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*Port .*/Port 2222/g' /etc/sshd_config
    sudo sed -i 's/.*Protocol .*/Protocol 2/g' /etc/sshd_config
    sudo sed -i 's/.*UsePAM .*/UsePAM yes/g' /etc/ssh/sshd_config
    sudo sed -i 's/.*X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
    sudo systemctl restart sshd 2>/dev/null
    sudo systemctl restart ssh 2>/dev/null
  fi
elif [ "$QUESTION" = 'No' ]
then
  if [ "$SSH" = 'ii' ]
  then
    sudo systemctl disable sshd
    sudo systemctl stop sshd
    sudo apt-get purge -y openssh-server
    PORT=$(cat /etc/ssh/sshd_config | grep "Port " | awk '{print $2}')
    sudo ufw status | grep -v "Status\|To\|---" | nl | grep " SSH\| OpenSSH\| $PORT/tcp\| $PORT/udp" | awk '{print $1}' | sort -nr | sudo xargs ufw --force delete $0
  fi
fi

echo -e $BLUE"Is Apache needed?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  if [ "$APACHE" = 'ii' ]
  then
    sudo sed -i 's/^mod_imap/#mod_imap/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_include/#mod_include/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_info/#mod_info/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_userdir/#mod_userdir/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_autoindex/#mod_autoindex/g' /etc/apache2/apache2.conf
    sudo systemctl restart apache2
  fi
elif [ "$QUESTION" = 'No' ]
then
  if [ "$APACHE" = 'ii' ]
  then
    sudo systemctl stop apache2
    sudo apt-get purge -y apache2*
  fi
fi

echo -e $BLUE"Is FTP needed?"$ENDCOLOR
select QUESTION in Yes No;
do
  break;
done
if [ "$QUESTION" = 'Yes' ]
then
  if [ "$VSFTP" = 'ii' ]
  then
    sudo sed -i 's/.*anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf
    sudo sed -i 's/.*local_enable=NO/local_enable=YES/g' /etc/vsftpd/vsftpd.conf
    sudo systemctl restart vsftp
    sudo chkconfig vsftpd on
  fi
  if [ "$PUREFTPD" = 'ii' ]
  then
    echo 2 | sudo tee /etc/pure-ftpd/conf/TLS
  fi
elif [ "$QUESTION" = 'No' ]
then
  if [ "$VSFTP" = 'ii' ]
  then
    sudo systemctl disable vsftp
    sudo systemctl stop vsftp
    sudo apt-get purge -y vsftp
  fi
  if [ "$PUREFTPD" = 'ii' ]
  then
    sudo systemctl disable pure-ftpd
    sudo systemctl stop pure-ftpd
    sudo apt-get purge -y pure-ftpd
  fi
fi

# End of script
echo -e $GREEN"Setting correct permissions for files."$ENDCOLOR
sudo chmod -R 444 /var/log
sudo chmod -R 444 /etc/ssh
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 600 /etc/ssh/sshd_config
sudo chown root:root /etc/fstab
sudo chown root:root /etc/grub.conf
sudo chmod og-rwx /etc/grub.conf
sudo chmod 644 /etc/passwd
sudo chown root:root /etc/passwd
sudo chmod 644 /etc/group
sudo chown root:root /etc/group
sudo chmod 600 /etc/shadow
sudo chown root:root /etc/shadow
sudo chmod 600 /etc/gshadow
sudo chown root:root /etc/gshadow

unset MEMORY_SHUFFLING
unset MEMORY_SHUFFLING_FILE
unset SUID_DUMPABLE
unset KERNEL_EXEC
unset IP_FORWARDING
unset PACKET_REDIRECTS_1
unset PACKET_REDIRECTS_2
unset ICMP_REDIRECT_1
unset ICMP_REDIRECT_2
unset MESSAGE_PROTECTION
unset BOOT_DIRECTORY
unset UFW_STATUS
unset GUEST_ACCOUNT
unset SSH
unset OPEN_FW
unset VSFTP
unset PUREFTPD
unset QUESTION
