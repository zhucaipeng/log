#!/bin/bash

##备份策略：每天将接收到的原始日志进行格式处理后同时进行备份！

rclxlog='/data/logs/receive_linux.log'
savepath='/data/logs/backup/linux'
[ -e $savepath/$(date +%Y)/$(date +%m) ] || mkdir -p $savepath/$(date +%Y)/$(date +%m)
count=$(ls $savepath/$(date +%Y)/$(date +%m)/$(date +%Y%m%d).lx.log 2> /dev/null |wc -l)

[ ! -s "$rclxlog" ] && echo “"$rclxlog"内容为空,无需备份”  && exit

if [ $count -ne 0 ];then
	echo "今日已自动备份！请勿重复备份！以防覆盖！"
	exit 1
else
	awk 'NF>10{print $0}' $rclxlog |awk 'NF<=11 && $11 !~ /\<ls\>|\<ll\>/ || NF>11{print $0}' > mylog.txt
	awk '{printf"%-30s\t%-16s\t%-5s\t%-15s\t%-20s\t%-10s\n",$5,$6,$7,$8,$9,$10}' mylog.txt  > 1.txt
	awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10="";print}' mylog.txt |sed 's/^[[:space:]]\{0,\}//g' > 2.txt
	paste 1.txt 2.txt > $savepath/$(date +%Y)/$(date +%m)/$(date +%Y%m%d).lx.log
	rm -rf {mylog,1,2}.txt
	
	mv $rclxlog  $savepath/$(date +%Y)/$(date +%m)/$(date +%Y%m%d).lx.original.log
  	/bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
fi
