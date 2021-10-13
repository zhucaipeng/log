#!/bin/bash

##备份策略：每天将接收到的原始日志进行格式处理后同时进行备份！

rcaixlog='/data/logs/receive_aix.log'
savepath='/data/logs/backup/aix'
[ -e $savepath/$(date +%Y)/$(date +%m) ] || mkdir -p $savepath/$(date +%Y)/$(date +%m)
count=$(ls $savepath/$(date +%Y)/$(date +%m)/$(date +%Y%m%d).aix.log 2> /dev/null |wc -l)

[ ! -s "$rcaixlog" ] && echo “"$rcaixlog"内容为空,无需备份”  && exit

if [ $count -ne 0 ];then
	echo "今日已自动备份！请勿重复备份！以防覆盖！"
	exit 1
else
	awk 'NF>13{print $0}' $rcaixlog |awk 'NF<=14 && $14 !~ /\<ls\>/ || NF>14{print $0}' > aix.txt
	awk '{printf"%-30s\t%-20s\t%-5s\t%-15s\t%-20s\t%-10s\n",$8,$9,$10,$11,$12,$13}' aix.txt  > aix1.txt
	awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=$11=$12=$13="";print}' aix.txt |sed 's/^[[:space:]]\{0,\}//g' > aix2.txt
	paste aix1.txt aix2.txt > $savepath/$(date +%Y)/$(date +%m)/$(date +%Y%m%d).aix.log
	rm -rf {aix,aix1,aix2}.txt
	
	mv $rcaixlog  $savepath/$(date +%Y)/$(date +%m)/$(date +%Y%m%d).aix.original.log
  	/bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
fi
