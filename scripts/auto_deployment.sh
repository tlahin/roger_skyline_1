#!/bin/sh

DEPLOYMENT_DIR='/usr/scripts/deployment'
WEB_DIR='/var/www/html'
LOG='/var/log/auto_deployment.log'

DIFF=`diff -q $DEPLOYMENT_DIR $WEB_DIR`

if [ ! -z "$DIFF" ]; then
	sudo cp -v $DEPLOYMENT_DIR/* $WEB_DIR
	echo "New version deployed." >> $LOG
	echo $(date) >> $LOG
	echo '' >> $LOG
else
	echo "No new changes. Newest version already deployed." >> $LOG
	echo $(date) >> $LOG
	echo '' >> $LOG
fi
