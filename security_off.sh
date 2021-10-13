#!/bin/bash

sed -i '/^[ ]\{0,0\}export HISTTIMEFORMAT="%F %T "/d'  /etc/bashrc
source /etc/bashrc

sed -i '/* soft core 102400/,/* soft nproc 5000/d' /etc/security/limits.conf

grep -v -E ^[[:space:]]*# /etc/fstab |grep -v -E [[:space:]]+"/tmp|/var|/home"[[:space:]]+ |grep -E "[[:space:]]+ext[3|4][[:space:]]+" |grep "errors=panic" &> /dev/null
if [ $? -eq 0 ];then
	sed -i "/^[^ \{0,\}#]/{/[[:space:]]\{1,\}ext[3|4][[:space:]]\{1,\}/{s/,errors=panic//g}}"   /etc/fstab &> /dev/null
fi
TMP=`grep -v -E ^[[:space:]]*# /etc/fstab |grep -E "[[:space:]]+/tmp[[:space:]]+" |awk '{print $4}'`
VAR=`grep -v -E ^[[:space:]]*# /etc/fstab |grep -E "[[:space:]]+/var[[:space:]]+" |awk '{print $4}'`
HOME=`grep -v -E ^[[:space:]]*# /etc/fstab |grep -E "[[:space:]]+/home[[:space:]]+" |awk '{print $4}'`
sed -i "/^[^#]/{/[[:space:]]\{1,\}\/tmp[[:space:]]\{1,\}/{s/"$TMP"/defaults/g}}"    /etc/fstab &> /dev/null
sed -i "/^[^#]/{/[[:space:]]\{1,\}\/var[[:space:]]\{1,\}/{s/"$VAR"/defaults/g}}"    /etc/fstab &> /dev/null
sed -i "/^[^#]/{/[[:space:]]\{1,\}\/home[[:space:]]\{1,\}/{s/"$HOME"/defaults/g}}"  /etc/fstab &> /dev/null

sed -i '/\-a exit,always -F arch=b64 -S execve -k exec/,/\-w \/etc\/multipath.conf -p wa -k multipth/d' /etc/audit/audit.rules
sed -i 's/num_logs = 4/num_logs = 5/g' /etc/audit/auditd.conf
sed -i 's/max_log_file = 50/max_log_file = 6/g' /etc/audit/auditd.conf
sed -i 's/crashkernel=[[:digit:]][[:digit:]][[:digit:]]M/crashkernel=auto/g' /etc/grub.conf
sed -i '/install usb-storage \/bin\/true/d' /etc/modprobe.d/usb-storage.conf &> /dev/null
sed -i '/password --md5/d' /boot/grub/grub.conf
sed -i 's/#*start on control-alt-delete/start on control-alt-delete/g' /etc/init/control-alt-delete.conf

sed -i '/^[ ]*PASS_MAX_DAYS/{s/[[:digit:]]\{1,\}/99999/g}' /etc/login.defs
sed -i '/^[ ]*PASS_MIN_DAYS/{s/[[:digit:]]\{1,\}/0/g}' /etc/login.defs
sed -i '/^[ ]*PASS_MIN_LEN/{s/[[:digit:]]\{1,\}/5/g}' /etc/login.defs
sed -i '/^[ ]*PASS_WARN_AGE/{s/[[:digit:]]\{1,\}/7/g}' /etc/login.defs
sed -i 's/password[[:space:]]\{1,\}requisite[[:space:]]\{1,\}pam_cracklib.so.*/password    requisite     pam_cracklib.so try_first_pass retry=3 type=/g'  /etc/pam.d/system-auth-ac

sed -i '/LOG_UNKFAIL_ENAB[[:space:]]\{1,\}no/d' /etc/login.defs
sed -i '/LASTLOG_ENAB[[:space:]]\{1,\}yes/d' /etc/login.defs 

sed -i '/export TMOUT=300/d' /etc/profile
sed -i '/export HISTFILESIZE=5000/d' /etc/profile
source /etc/profile

sed -i '/auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so[[:space:]]\+onerr=fail deny=6 unlock_time=300 even_deny_root root_unlock_time=300/d' /etc/pam.d/system-auth-ac
sed -i '/account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so/d'  /etc/pam.d/system-auth-ac
sed -i '/auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so[[:space:]]\+onerr=fail deny=6 unlock_time=300 even_deny_root root_unlock_time=300/d' /etc/pam.d/password-auth-ac
sed -i '/account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so/d' /etc/pam.d/password-auth-ac

sed -i 's/Port 22/#Port 22/g' /etc/ssh/sshd_config
sed -i 's/LogLevel INFO/#LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/MaxAuthTries 3/#MaxAuthTries 6/g' /etc/ssh/sshd_config
sed -i 's/RhostsRSAAuthentication no/#RhostsRSAAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords no/#PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/StrictModes yes/#StrictModes yes/g' /etc/ssh/sshd_config
sed -i 's/IgnoreUserKnownHosts no/#IgnoreUserKnownHosts yes/g' /etc/ssh/sshd_config
sed -i '/Ciphers 3des-cbc/d' /etc/ssh/sshd_config
sed -i '/MACs hmac-sha1,hmac-md5/d' /etc/ssh/sshd_config
service sshd restart &> /dev/null

sed -i '/net.ipv4.conf.all.arp_ignore = 0/,/net.ipv4.tcp_keepalive_intvl = 6/d' /etc/sysctl.conf 
sysctl -p &> /dev/null


