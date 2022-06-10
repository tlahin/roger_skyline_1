#!/bin/sh

echo UPDATING PACKAGES >> /var/log/auto_update.log
echo $(date) >> /var/log/auto_update.log
echo `sudo apt-get update --yes` >> /var/log/auto_update.log
echo `sudo apt-get upgrade --yes` >> /var/log/auto_update.log
echo '' >> /var/log/auto_update.log
