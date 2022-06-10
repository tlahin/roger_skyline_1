#!/bin/sh

CRONTAB='/var/spool/cron/crontabs/root'
BACKUP='/var/spool/cron/crontabs/root.backup'

DIFF=`diff $CRONTAB $BACKUP`
if [ ! -z "$DIFF" ]; then
	echo "Changes in CRONTAB file." | mail -s "Crontab modifed" root	
fi

cp $CRONTAB $BACKUP
