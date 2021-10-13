#!/bin/bash

service cups stop &> /dev/null
service postfix stop &> /dev/null
service pcscd stop &> /dev/null
service smartd stop &> /dev/null
service alsasound stop &> /dev/null
service iscsitarget stop &> /dev/null
service smb stop &> /dev/null
service acpid stop &> /dev/null
service iptables stop &> /dev/null
service ip6tables stop &> /dev/null

chkconfig cups off  &> /dev/null
chkconfig postfix off &> /dev/null
chkconfig pcscd off &> /dev/null
chkconfig smartd off &> /dev/null
chkconfig alsasound off &> /dev/null
chkconfig iscsitarget off &> /dev/null
chkconfig smb off &> /dev/null
chkconfig acpid off &> /dev/null
chkconfig iptables off &> /dev/null
chkconfig ip6tables off &> /dev/null

grep -E '^[[:space:]]*server[[:space:]]+192.168.0.8' /etc/ntp.conf &> /dev/null
if [ $? -ne 0 ];then
	echo "server 192.168.0.8" >> /etc/ntp.conf
	service ntpd restart &> /dev/null
fi

sed -i '/^[[:space:]]\{0,\}export[[:space:]]\{1,\}HISTTIMEFORMAT=.*/d' /etc/bashrc
echo 'export HISTTIMEFORMAT="%F_%T `whoami` `echo -n " "`"' >> /etc/bashrc

grep -E '^[[:space:]]*\*[[:space:]]+soft[[:space:]]+nproc[[:space:]]+1024' /etc/security/limits.d/90-nproc.conf &> /dev/null
if [ $? -eq 0 ];then
	sed -i 's/^[[:space:]]\{0,\}\*\([[:space:]]\{1,\}soft[[:space:]]\{1,\}nproc[[:space:]]\{1,\}1024\)/#*\1/g' /etc/security/limits.d/90-nproc.conf
fi

grep -E '^[[:space:]]*\*[[:space:]]+soft[[:space:]]+core' /etc/security/limits.conf &> /dev/null
if [ $? -eq 1 ];then
	cat >> /etc/security/limits.conf << EOF
* soft core 102400
* hard core 102400
* hard nofile 5000
* soft nofile 5000
* hard nproc 5000
* soft nproc 5000
EOF
fi

grep  -E "^cmbjboss|^qappsom" /etc/passwd &> /dev/null
if [ $? -eq 0 ];then
        for I in `grep  -E "^cmbjboss|^qappsom" /etc/passwd |cut -d":" -f1`
        do
                grep -E "^[[:space:]]*${I}[[:space:]]+soft[[:space:]]+core" /etc/security/limits.conf &> /dev/null
                if [ $? -eq 1 ];then
                cat >> /etc/security/limits.conf << EOF
$I soft core unlimited
$I hard core unlimited
$I soft nofile 65535
$I hard nofile 65535
$I soft nproc 65535
$I hard nproc 65535
EOF
                fi
        done
fi

#grep -v -E ^[[:space:]]*# /etc/fstab |grep -v -E [[:space:]]+"/tmp|/var|/home"[[:space:]]+ |grep -E "[[:space:]]+ext[3|4][[:space:]]+" |grep "errors=panic" &> /dev/null
#if [ $? -eq 1 ];then
#	sed -i "/^[^ \{0,\}#]/{/[[:space:]]\{1,\}ext[3|4][[:space:]]\{1,\}/{s/\(defaults\)/\1,errors=panic/g}}"    		/etc/fstab &> /dev/null
#fi
#TMP=`grep -v -E ^[[:space:]]*# /etc/fstab |grep -E "[[:space:]]+/tmp[[:space:]]+" |awk '{print $4}'`
#VAR=`grep -v -E ^[[:space:]]*# /etc/fstab |grep -E "[[:space:]]+/var[[:space:]]+" |awk '{print $4}'`
#HOME=`grep -v -E ^[[:space:]]*# /etc/fstab |grep -E "[[:space:]]+/home[[:space:]]+" |awk '{print $4}'`
#sed -i "/^[^ \{0,\}#]/{/[[:space:]]\{1,\}\/tmp[[:space:]]\{1,\}/{s/"$TMP"/defaults,errors=panic,nodev,nosuid/g}}"    /etc/fstab &> /dev/null
#sed -i "/^[^ \{0,\}#]/{/[[:space:]]\{1,\}\/var[[:space:]]\{1,\}/{s/"$VAR"/defaults,errors=panic,nodev,nosuid/g}}"    /etc/fstab &> /dev/null
#sed -i "/^[^ \{0,\}#]/{/[[:space:]]\{1,\}\/home[[:space:]]\{1,\}/{s/"$HOME"/defaults,errors=panic,nosuid/g}}"    	/etc/fstab &> /dev/null

chmod 400 /etc/crontab &> /dev/null 
chmod 400 /etc/securetty &> /dev/null
chmod 600 /boot/grub/grub.conf  &> /dev/null
chmod 600 /etc/inittab &> /dev/null
chmod 600 /etc/login.defs &> /dev/null
chmod 000 /etc/shadow &> /dev/null
chmod 000 /etc/gshadow &> /dev/null

grep '\-a exit,always -F arch=b64 -S execve -k exec' /etc/audit/audit.rules &> /dev/null
if [ $? -eq 1 ];then
cat >> /etc/audit/audit.rules << EOF
-a exit,always -F arch=b64 -S execve -k exec
-a exit,always -F arch=b32 -S execve -k exec
-w /etc/crontab -p wa -k crontab
-w /etc/hosts -p wa -k hosts
-w /etc/hosts.allow -p wa -k hosts-allow
-w /etc/hosts.deny -p wa -k hosts-deny
-w /etc/fstab -p wa -k fstab
-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group -p wa -k group
-w /etc/gshadow -p wa -k gshadow
-w /etc/ntp.conf -p wa -k ntp
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/security/limits.conf -p wa -k limits
-w /boot/grub/grub.conf -p wa -k grub
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/udev/rules.d/ -p wa -k udev
-w /etc/profiles -p wa -k profile
-w /etc/kdump.conf -p wa -k kdump
-w /etc/lvm/lvm.conf -p wa -k lvm
-w /etc/login.defs -p wa -k login-defs
-w /etc/rsyslog.conf -p wa -k rsyslog
-w /etc/sysconfig/i18n -p wa -k i18n
-w /etc/sysconfig/network -p wa -k network
-w /etc/multipath.conf -p wa -k multipth
EOF
fi

sed -i 's/num_logs = [[:digit:]]\{1,\}/num_logs = 4/g' /etc/audit/auditd.conf
sed -i 's/max_log_file = [[:digit:]]\{1,\}/max_log_file = 50/g' /etc/audit/auditd.conf
sed -i 's/flush = INCREMENTAL/flush = NONE/g' /etc/audit/auditd.conf
service auditd restart &> /dev/null 
chkconfig auditd on &> /dev/null

mem=$[`cat /proc/meminfo  |grep MemTotal |awk '{print $2}'`/1024]
if [[ $mem -gt 0 && $mem -lt 2048 ]];then
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=128M/g' /etc/grub.conf	/boot/grub/grub.conf 
elif [[ $mem -ge 2048 && $mem -lt 6144 ]];then
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=256M/g' /etc/grub.conf	/boot/grub/grub.conf 
elif [[ $mem -ge 6144 && $mem -lt 8192 ]];then
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=512M/g' /etc/grub.conf	/boot/grub/grub.conf 
else
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=768M/g' /etc/grub.conf	/boot/grub/grub.conf 
fi
service kdump restart  &> /dev/null
chkconfig kdump on  &> /dev/null

sed -i 's/MAILTO=root/MAILTO=""/g' /etc/crontab
service crond restart &> /dev/null 

grep "install usb-storage /bin/true" /etc/modprobe.d/usb-storage.conf &> /dev/null
if [ $? -eq 1 ];then
	echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
fi

grub加密
!( rpm -qa |grep expect &> /dev/null ) && yum install expect -y
grep -E "^[[:space:]]*password[[:space:]]+--md5" /boot/grub/grub.conf &> /dev/null
if [ $? -eq 1 ];then
grubpassword=`expect << EOF |tail -1
			  spawn grub-md5-crypt
			  expect "Password:"
			  send "123456\r"
			  expect "Retype password:"
			  send "123456\r"
			  expect eof
EOF`
sed -i "/^[ ]\{0,\}splashimage/a\password --md5 $grubpassword" /boot/grub/grub.conf
fi

sed -i 's/^[ ]\{0,\}start on control-alt-delete/#start on control-alt-delete/g' /etc/init/control-alt-delete.conf

#打开口令有效期规定
sed -i '/^[ ]\{0,\}PASS_MAX_DAYS/{s/[[:digit:]]\{1,\}/90/g}' /etc/login.defs
sed -i '/^[ ]\{0,\}PASS_MIN_DAYS/{s/[[:digit:]]\{1,\}/1/g}' /etc/login.defs
sed -i '/^[ ]\{0,\}PASS_MIN_LEN/{s/[[:digit:]]\{1,\}/8/g}' /etc/login.defs
sed -i '/^[ ]\{0,\}PASS_WARN_AGE/{s/[[:digit:]]\{1,\}/7/g}' /etc/login.defs
sed -i 's/^[ ]\{0,\}password[[:space:]]\{1,\}requisite[[:space:]]\{1,\}pam_cracklib.so.*/password    requisite     pam_cracklib.so try_first_pass retry=6 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/g'  /etc/pam.d/system-auth-ac

#关闭口令有效期规定
#sed -i '/^[ ]*PASS_MAX_DAYS/{s/[[:digit:]]\{1,\}/99999/g}' /etc/login.defs
#sed -i '/^[ ]*PASS_MIN_DAYS/{s/[[:digit:]]\{1,\}/0/g}' /etc/login.defs
#sed -i '/^[ ]*PASS_MIN_LEN/{s/[[:digit:]]\{1,\}/5/g}' /etc/login.defs
#sed -i '/^[ ]*PASS_WARN_AGE/{s/[[:digit:]]\{1,\}/7/g}' /etc/login.defs

grep -E "^[[:space:]]*LOG_UNKFAIL_ENAB[[:space:]]+yes" /etc/login.defs &> /dev/null
if [ $? -eq 1 ];then
	echo "LOG_UNKFAIL_ENAB		 yes" >> /etc/login.defs
fi

grep -E "^[[:space:]]*LASTLOG_ENAB[[:space:]]+yes" /etc/login.defs &> /dev/null
if [ $? -eq 1 ];then
	echo "LASTLOG_ENAB           yes" >> /etc/login.defs
fi

grep "^[[:space:]]*export[[:space:]]+TMOUT=300" /etc/profile &> /dev/null
if [ $? -eq 1 ];then
	echo "export TMOUT=300" >> /etc/profile
fi

grep "^[[:space:]]*export[[:space:]]+HISTFILESIZE=5000" /etc/profile &> /dev/null
if [ $? -eq 1 ];then
	echo "export HISTFILESIZE=5000" >> /etc/profile
fi

source /etc/profile

#连续6次输错密码禁用一段时间
grep -E "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_tally2.so[[:space:]]+onerr=fail deny=6 unlock_time=300 even_deny_root root_unlock_time=300" /etc/pam.d/system-auth-ac &> /dev/null 
if [ $? -eq 1 ];then
	sed -i  "/auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_env.so/a\auth        required      pam_tally2.so    onerr=fail deny=6 unlock_time=300 even_deny_root root_unlock_time=300" /etc/pam.d/system-auth-ac
fi

grep  -E "^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_tally2.so" /etc/pam.d/system-auth-ac &> /dev/null
if [ $? -eq 1 ];then
	sed -i "/account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_unix.so/i\account     required      pam_tally2.so" /etc/pam.d/system-auth-ac
fi

grep -E "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_tally2.so[[:space:]]+onerr=fail deny=6 unlock_time=300 even_deny_root root_unlock_time=300" /etc/pam.d/password-auth-ac &> /dev/null 
if [ $? -eq 1 ];then
	 sed -i "/auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_env.so/a\auth        required      pam_tally2.so    onerr=fail deny=6 unlock_time=300 even_deny_root root_unlock_time=300" /etc/pam.d/password-auth-ac
fi

grep -E "^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_tally2.so" /etc/pam.d/password-auth-ac &> /dev/null
if [ $? -eq 1 ];then
	sed -i "/account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_unix.so/i\account     required      pam_tally2.so" /etc/pam.d/password-auth-ac
fi

#关闭连续6次输错密码禁用一段时间
#sed -i '/auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so[[:space:]]\{1,\}onerr=fail[[:space:]]\{1,\}deny=6[[:space:]]\{1,\}unlock_time=300[[:space:]]\{1,\}#even_deny_root[[:space:]]\{1,\}root_unlock_time=300/d' /etc/pam.d/system-auth-ac
#sed -i '/account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so/d'  /etc/pam.d/system-auth-ac
#sed -i '/auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so[[:space:]]\{1,\}onerr=fail[[:space:]]\{1,\}deny=6[[:space:]]\{1,\}unlock_time=300[[:space:]]\{1,\}#even_deny_root[[:space:]]\{1,\}root_unlock_time=300/d' /etc/pam.d/password-auth-ac
#sed -i '/account[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_tally2.so/d' /etc/pam.d/password-auth-ac

rm -rf /root/.rhosts  /root/.shosts  /etc/hosts.equiv  /etc/shosts.equiv &> /dev/null

sed -i 's/#*Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/#*LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/#*MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config
sed -i 's/#*RhostsRSAAuthentication no/RhostsRSAAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#*PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/#*StrictModes yes/StrictModes yes/g' /etc/ssh/sshd_config

grep "Ciphers 3des-cbc" /etc/ssh/sshd_config &> /dev/null
if [ $? -eq 1 ];then
	echo "Ciphers 3des-cbc" >> /etc/ssh/sshd_config
fi

grep "MACs hmac-sha1,hmac-md5" /etc/ssh/sshd_config &> /dev/null
if [ $? -eq 1 ];then
        echo "MACs hmac-sha1,hmac-md5" >> /etc/ssh/sshd_config
fi

service sshd restart &> /dev/null

grep  -E 'net.ipv4.conf.all.arp_ignore[[:space:]]*=[[:space:]]*0' /etc/sysctl.conf &> /dev/null
if [ $? -eq 1 ];then
	cat >> /etc/sysctl.conf << EOF
net.ipv4.conf.all.arp_ignore = 0
net.ipv4.conf.default.arp_ignore = 0
net.ipv4.conf.all.arp_filter = 0
net.ipv4.conf.default.arp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.all.log_martians =0
net.ipv4.conf.default.log_martians = 0
net.ipv4.conf.all.promote_secondaries = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.tcp_timestamps = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.default.proxy_arp = 0
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 60
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_keepalive_time = 150
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 6
EOF
fi

grep "vm.min_free_kbytes"  /etc/sysctl.conf &> /dev/null
if [ $? -eq 1 ];then
	new_mem=$[$mem*1024/10]
	cat >> /etc/sysctl.conf << EOF
vm.min_free_kbytes = 16384
vm.vfs_cache_pressure = 100
vm.dirty_ratio = 40
vm.page-cluster = 3
fs.file-max = $new_mem
kernel.shmmni = 4096
kernel.core_uses_pid = 0
kernel.core_pattern = corefile/core-%e
kernel.sysrq = 1
EOF
fi

sysctl -p &> /dev/null
