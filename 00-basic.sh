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

bred="\033[1;31m"
blue="\033[0;34m"
green="\033[0;32m"
endcolor="\033[0m"

# Hardening Variables
memory_shuffling=$(cat /proc/sys/kernel/randomize_va_space)
memory_shuffling_file=$(cat /etc/sysctl.conf | grep '^kernel.randomize_va_space')
suid_dumpable=$(cat /etc/sysctl.conf | grep '^fs.suid_dumpable')
kernel_exec=$(cat /etc/sysctl.conf | grep '^kernel.exec-shield')
ip_forwarding=$(cat /etc/sysctl.conf | grep '^net.ipv4.ip_forward')
packet_redirects_1=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.all.send_redirects')
packet_redirects_2=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.default.send_redirects')
icmp_redirect_1=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.all.accept_redirects')
icmp_redirect_2=$(cat /etc/sysctl.conf | grep '^net.ipv4.conf.default.accept_redirects')
message_protection=$(cat /etc/sysctl.conf | grep '^net.ipv4.icmp_ignore_bogus_error_responses')
#BOOT_DIRECTORY=$(cat /etc/fstab | grep '^LABEL=/boot')

# Other Variables
ufw_status=$(sudo ufw status | grep 'Status:')
guest_account=$(cat /etc/lightdm/lightdm.conf 2>/dev/null | grep "allow-guest")

# Service Variables
ssh=$(dpkg -l 2>/dev/null | grep "openssh-server" | tail -n 1 | awk '{print $1}')
apache=$(dpkg -l 2>/dev/null | grep "apache2" | tail -n 1 | awk '{print $1}')
vsftp=$(dpkg -l 2>/dev/null | grep "vsftpd" | tail -n 1 | awk '{print $1}')
pureftpd=$(dpkg -l 2>/dev/null | grep "pure-ftpd" | tail -n 1 | awk '{print $1}')

echo -e $bred"Root permissions are required to run this script."$endcolor
sudo echo ""
mkdir $PWD/backups
clear

echo -e $blue"Do you want to enable memory shuffling?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  if [[ "$memory_shuffling" != "2" ]]
  then
    sudo su -c "echo '2' > /proc/sys/kernel/randomize_va_space"
  fi
  if [[ "$memory_shuffling_file" != "kernel.randomize_va_space" ]]
  then
    echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$memory_shuffling_file" != "kernel.randomize_va_space = 2" ]]
  then
    sudo sed -i 's/^kernel.randomize_va_space = ?/kernel.randomize_va_space = 2/g' /etc/sysctl.conf
  fi
fi

echo -e $blue"Do you want to enable firewall?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  if [[ "$ufw_status" != "Status: active" ]]
  then
    sudo ufw enable
  fi
  sudo ufw logging on
  sudo ufw logging high
  open_fw=$(sudo ufw status | grep -v "Status\|To\|---" | nl | tail -n1)
  if [[ "$open_fw" -ge '1' ]]
  then
    echo -e $green"Outputting open firewall ports to $PWD/open-fw.txt"$endcolor
    sudo ufw status | tee ./open-fw.txt
  fi
fi

echo -e $blue"Do you want to disable guest?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  if [[ "$guest_account" != "allow-guest=false" ]]
  then
    cp /etc/lightdm/lightdm.conf $PWD/backups/lightdm.conf.bak 2>/dev/null
    sudo sed -i 's/allow-guest=true/allow-guest=false/g' /etc/lightdm/lightdm.conf 2>/dev/null
    sudo /usr/lib/lightdm/lightdm-set-defaults -l false 2>/dev/null
  fi
fi

echo -e $blue"Do you want to set password policies?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
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

echo -e $blue"Do you want to list and save users?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  eval getent passwd {"$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)".."$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)"} > users.txt
fi

echo -e $blue"Do you want to enable misc hardening?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  echo 'hard nproc $(ps aux -L | cut --delimiter=" " --fields=1 | sort | uniq --count | sort --numeric-sort | tail --lines=1)' | sudo tee -a /etc/security/limits.conf > /dev/null
  echo 'hard core 0' | sudo tee -a /etc/security/limits.conf > /dev/null
  if [[ "$suid_dumpable" != "^fs.suid_dumpable" ]]
  then
    echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$suid_dumpable" != "^fs.suid_dumpable = 0" ]]
  then
    sudo sed -i 's/^fs.suid_dumpable = ?/fs.suid_dumpable = 0/g' /etc/sysctl.conf
  fi
  if [[ "$kernel_exec" != "^kernel.exec-shield" ]]
  then
    echo "kernel.exec-shield = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$kernel_exec" != "^kernel.exec-shield = 1" ]]
  then
    sudo sed -i 's/^kernel.exec-shield = ?/kernel.exec-shield = 1/g'
  fi
  if [[ "$ip_forwarding" != "^net.ipv4.ip_forward" ]]
  then
    echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$ip_forwarding" != "^net.ipv4.ip_forward = 0" ]]
  then
    sudo sed -i 's/^net.ipv4.ip_forward = ?/net.ipv4.ip_forward = 0/g' /etc/sysctl.conf
  fi
  if [[ "$packet_redirects_1" != "^net.ipv4.conf.all.send_redirects" ]]
  then
    echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$packet_redirects_1" != "^net.ipv4.conf.all.send_redirects = 0" ]]
  then
    sudo sed -i 's/^net.ipv4.conf.all.send_redirects = ?/net.ipv4.conf.all.send_redirects = 0/g' /etc/sysctl.conf
  fi
  if [[ "$packet_redirects_2" != "^net.ipv4.conf.default.send_redirects" ]]
  then
    echo "net.ipv4.conf.default.send_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$packet_redirects_2" != "^net.ipv4.conf.default.send_redirects = 0" ]]
  then
    sudo sed -i 's/^net.ipv4.conf.default.send_redirects = ?/net.ipv4.conf.default.send_redirects = 0/g' /etc/sysctl.conf
  fi
  if [[ "$icmp_redirect_1" != "^net.ipv4.conf.all.accept_redirects" ]]
  then
    echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$icmp_redirect_1" != "^net.ipv4.conf.all.accept_redirects = 0" ]]
  then
    sudo sed -i 's/^net.ipv4.conf.all.accept_redirects = ?/net.ipv4.conf.all.accept_redirects = 0/g' /etc/sysctl.conf
  fi
  if [[ "$icmp_redirect_2" != "^net.ipv4.conf.default.accept_redirects" ]]
  then
    echo "net.ipv4.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$icmp_redirect_2" != "^net.ipv4.conf.default.accept_redirects = 0" ]]
  then
    sudo sed -i 's/^net.ipv4.conf.default.accept_redirects = ?/net.ipv4.conf.default.accept_redirects = 0/g' /etc/sysctl.conf
  fi
  if [[ "$message_protection" != "^net.ipv4.icmp_ignore_bogus_error_responses" ]]
  then
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 0" | sudo tee -a /etc/sysctl.conf > /dev/null
  elif [[ "$icmp_redirect_2" != "^net.ipv4.icmp_ignore_bogus_error_responses = 0" ]]
  then
    sudo sed -i 's/^net.ipv4.icmp_ignore_bogus_error_responses = ?/net.ipv4.icmp_ignore_bogus_error_responses = 0/g' /etc/sysctl.conf
  fi
fi

echo -e $blue"Do you want to remove hacking tools and games?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  cat games.txt | xargs sudo apt-get purge -y
  cat hacking-tools.txt | xargs sudo apt-get purge -y
fi

echo -e $blue"Do you want to list users with blank passwords?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  sudo awk -F: '$2 == "" {print $1, "has no password!" }' /etc/shadow | tee ./blank-passwords.txt
fi

echo -e $blue"Do you want to install and run ClamAV?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  sudo apt-get install -y clamav
  sudo freshclam
  sudo clamscan --max-filesize=3999M --max-scansize=3999M --exclude-dir=/sys/* -i -r /
fi

echo -e $blue"Do you want to list all cron tabs?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  echo -e "/etc/cron.d is: $(ls /etc/cron.d)\n" > $PWD/crons.txt
  echo -e "Daily crons: $(ls /etc/cron.daily)\n" > $PWD/crons.txt
  echo -e "Hourly crons: $(ls /etc/cron.hourly)\n" > $PWD/crons.txt
  echo -e "Weekly crons: $(ls /etc/cron.weekly)\n" > $PWD/crons.txt
  echo -e "Monthly crons: $(ls /etc/cron.monthly)\n" > $PWD/crons.txt
fi

# Securing Services
echo -e $blue"Is ssh needed?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  if [[ "$ssh" = 'ii' ]]
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
elif [[ "$question" = 'No' ]]
then
  if [[ "$ssh" = 'ii' ]]
  then
    sudo systemctl disable sshd
    sudo systemctl stop sshd
    sudo apt-get purge -y openssh-server
    PORT=$(cat /etc/ssh/sshd_config | grep "Port " | awk '{print $2}')
    sudo ufw status | grep -v "Status\|To\|---" | nl | grep " ssh\| Openssh\| $PORT/tcp\| $PORT/udp" | awk '{print $1}' | sort -nr | sudo xargs ufw --force delete $0
  fi
fi

echo -e $blue"Is Apache needed?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  if [[ "$apache" = 'ii' ]]
  then
    sudo sed -i 's/^mod_imap/#mod_imap/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_include/#mod_include/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_info/#mod_info/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_userdir/#mod_userdir/g' /etc/apache2/apache2.conf
    sudo sed -i 's/^mod_autoindex/#mod_autoindex/g' /etc/apache2/apache2.conf
    sudo systemctl restart apache2
  fi
elif [[ "$question" = 'No' ]]
then
  if [[ "$apache" = 'ii' ]]
  then
    sudo systemctl stop apache2
    sudo apt-get purge -y apache2*
  fi
fi

echo -e $blue"Is FTP needed?"$endcolor
select question in Yes No;
do
  break;
done
if [[ "$question" = 'Yes' ]]
then
  if [[ "$vsftp" = 'ii' ]]
  then
    sudo sed -i 's/.*anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf
    sudo sed -i 's/.*local_enable=NO/local_enable=YES/g' /etc/vsftpd/vsftpd.conf
    sudo sed -i 's/.*anon_upload_enable/anon_upload_enable'
    sudo systemctl restart vsftp
    sudo chkconfig vsftpd on
  fi
  if [[ "$pureftpd" = 'ii' ]]
  then
    echo 2 | sudo tee /etc/pure-ftpd/conf/TLS
  fi
elif [[ "$question" = 'No' ]]
then
  if [[ "$vsftp" = 'ii' ]]
  then
    sudo systemctl disable vsftp
    sudo systemctl stop vsftp
    sudo apt-get purge -y vsftp
  fi
  if [[ "$pureftpd" = 'ii' ]]
  then
    sudo systemctl disable pure-ftpd
    sudo systemctl stop pure-ftpd
    sudo apt-get purge -y pure-ftpd
  fi
fi

# End of script
echo -e $green"Setting correct permissions for files."$endcolor
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

unset memory_shuffling
unset memory_shuffling_file
unset suid_dumpable
unset kernel_exec
unset ip_forwarding
unset packet_redirects_1
unset packet_redirects_2
unset icmp_redirect_1
unset icmp_redirect_2
unset message_protection
unset ufw_status
unset guest_account
unset ssh
unset open_fw
unset vsftp
unset pureftpd
unset question
