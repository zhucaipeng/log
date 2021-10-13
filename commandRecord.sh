#!/bin/bash

##中心主机配置
##vi /etc/sysconfig/rsyslog
##SYSLOGD_OPTIONS="-r -x -m 0"

##vi /etc/rsyslog.conf
##local6.*  /data/logs/receive_linux.log
##local4.*  /data/logs/receive_aix.log

ip=$(ifconfig |grep 'inet addr:' |grep -v '127.0.0.1' |awk '{print $2}' |cut -d":" -f2)
if [ "$ip" == "192.168.0.8" ];then
	echo "此脚本供其他机器加入审计使用，不能在日志采集服务器上执行！"
	exit 4
fi

sed -i '/^[[:space:]]\{0,\}export[[:space:]]\{1,\}HISTTIMEFORMAT=.*/d' /etc/bashrc
echo 'export HISTTIMEFORMAT="%F_%T `whoami` `echo -n " "`"' >> /etc/bashrc

grep '^[[:space:]]\{0,\}local6.*[[:space:]]\{1,\}@192.168.0.8' /etc/rsyslog.conf &> /dev/null
if [ $? -ne 0 ];then
        echo  "local6.*          @192.168.0.8" >> /etc/rsyslog.conf
fi

grep "/var/log/messages" /etc/rsyslog.conf  |grep "local6.none"  &> /dev/null
if [ $? -ne 0 ];then
	sed -i 's/\(^*.info;mail.none;authpriv.none;cron.none\)/\1;local6.none/g' /etc/rsyslog.conf
fi

sed -i 's/^[[:space:]]\{0,\}#*$ModLoad imudp/$ModLoad imudp/g' /etc/rsyslog.conf
sed -i 's/^[[:space:]]\{0,\}#*$UDPServerRun 514/$UDPServerRun 514/g' /etc/rsyslog.conf

grep 'function[[:space:]]\{1,\}bash2syslog'  /etc/profile &> /dev/null
if [ $? -ne 0 ];then
cat >> /etc/profile << EOF

function bash2syslog
{
  declare command
  declare source_ip
  declare ip
  declare st_uat
  declare env 
  declare login_time
  command=\$(history |tail -1 |sed 's/^[[:space:]]\{1,\}[[:digit:]]\{1,\}[[:space:]]\{1,\}\(.*\)/\1/g')
  source_ip=\$(who am i |sed -e 's/[()]//g' |awk '{print \$NF}')
  ip=\$(ifconfig |grep 'inet addr:' |grep -v '127.0.0.1' |awk '{print \$2}' |cut -d":" -f2 |head -1)
  st_uat=\$(echo "\$ip" |cut -d"." -f3)
  if [ \$st_uat -eq 73 ] || [ \$st_uat -eq 74 ] || [ \$st_uat -eq 90 ] || [ \$st_uat -eq 86 ] || [ \$st_uat -eq 59 ];then
         env=ST
  elif [ \$st_uat -eq 69 ] || [ \$st_uat -eq 70 ] || [ \$st_uat -eq 58 ] || [ \$st_uat -eq 87 ];then
         env=UAT
  elif [ \$st_uat -eq 81 ] || [ \$st_uat -eq 82 ];then
         env=STB
  elif [ \$st_uat -eq 77 ] || [ \$st_uat -eq 78 ];then
         env=UATB
  elif [ \$st_uat -eq 66 ];then
         env=MANAGER
  else
         env=UNKNOWN
  fi
  login_time=\$(who am i |awk '{print \$3"_"\$4}')
  [ -z "\$command" ] || logger -p local6.notice -t "\$source_ip" "\$login_time" "\$env" "\$ip" "\$command"

}
trap bash2syslog DEBUG
EOF
fi

service rsyslog restart &> /dev/null
source /etc/profile
source /etc/bashrc
