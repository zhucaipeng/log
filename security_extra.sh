#!/bin/bash

service iptables stop &> /dev/null
service ip6tables stop &> /dev/null

chkconfig iptables off &> /dev/null
chkconfig ip6tables off &> /dev/null

grep -E '^[[:space:]]*\*[[:space:]]+soft[[:space:]]+nproc[[:space:]]+1024' /etc/security/limits.d/90-nproc.conf &> /dev/null
if [ $? -eq 0 ];then
	sed -i 's/^[[:space:]]\{0,\}\*\([[:space:]]\{1,\}soft[[:space:]]\{1,\}nproc[[:space:]]\{1,\}1024\)/#*\1/g' /etc/security/limits.d/90-nproc.conf
fi

grep  -E "^cmbjboss|^qappsom" /etc/passwd &> /dev/null
if [ $? -eq 0 ];then
        for I in `grep  -E "^cmbjboss|^qappsom" /etc/passwd |cut -d":" -f1`
        do
                grep -E "${I}[[:space:]]+soft[[:space:]]+core[[:space:]]+unlimited" /etc/security/limits.conf &> /dev/null
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

sed -i 's/flush = INCREMENTAL/flush = NONE/g' /etc/audit/auditd.conf
service auditd restart &> /dev/null 
chkconfig auditd on

mem=$[`cat /proc/meminfo  |grep MemTotal |awk '{print $2}'`/1024]
if [[ $mem -gt 0 && $mem -lt 2048 ]];then
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=128M/g' /etc/grub.conf /boot/grub/grub.conf 
elif [[ $mem -ge 2048 && $mem -lt 6144 ]];then
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=256M/g' /etc/grub.conf /boot/grub/grub.conf 
elif [[ $mem -ge 6144 && $mem -lt 8192 ]];then
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=512M/g' /etc/grub.conf /boot/grub/grub.conf 
else
        sed -i  's/crashkernel=\(auto\|[0-9]\{1,\}M\)/crashkernel=768M/g' /etc/grub.conf /boot/grub/grub.conf 
fi
													  
chkconfig kdump on

sed -i 's/MAILTO=root/MAILTO=""/g' /etc/crontab
service crond restart &> /dev/null 