# Roger_skyline_1

  This project let's you discover the basics about system and network administration as well as a lots of services used on a server machine.
  
  - [Installing Virtual Machine](https://github.com/tlahin/roger_skyline_1/blob/main/README.md#installing-virtual-machine-1)
  - [Adding rights to sudo](https://github.com/tlahin/roger_skyline_1#adding-rights-to-sudo)
  - [Configuring static IP and a Netmask in \30](https://github.com/tlahin/roger_skyline_1#configuring-static-ip-and-a-netmask-in-30)
  - [Changing ssh port](https://github.com/tlahin/roger_skyline_1#changing-ssh-ports)
  - [SSH access with public keys and root access](https://github.com/tlahin/roger_skyline_1#ssh-access-with-public-keys-and-root-access)
  - [Firewall](https://github.com/tlahin/roger_skyline_1#firewall)
  - [DoS protection](https://github.com/tlahin/roger_skyline_1#dos-protection)
  - [Portscan protection](https://github.com/tlahin/roger_skyline_1#portscan-protection)
  - [Disable unused services](https://github.com/tlahin/roger_skyline_1#disable-unused-services)
  - [Script to update all the packages](https://github.com/tlahin/roger_skyline_1#script-to-update-all-the-packages)
  - [Script to monitor crontab changes](https://github.com/tlahin/roger_skyline_1#script-to-monitor-crontab-changes)
  - [Web part](https://github.com/tlahin/roger_skyline_1#web-part)
  - [SSL-sertificate](https://github.com/tlahin/roger_skyline_1#ssl-sertificate)
  - [Deployment automatization script](https://github.com/tlahin/roger_skyline_1/blob/main/README.md#deployment-automatization)

   Subject: [roger-skyline-1.5.en.pdf](https://github.com/tlahin/roger_skyline_1/files/8878592/roger-skyline-1.5.en.pdf)

# Installing Virtual Machine
  
  You have the freedom to install any linux OS you want!
  
  ❗ I chose to install Debian since I used it in INIT previously.
  
  First task is to set 8 GB of disk size to the VM and atleast one partition to be 4.2 GB
  
  Easily configured during the graphical installation of Debian.
  It's possible to check the size of the partitions with a command: `sudo fdisk -l`.
 
# New user and adding sudo rights

  To create a new user use command:

  `adduser username`.
  
  Add sudo rights with a following command:
  
  `usermod -aG sudo username`.
  
  - usermod is the tool that modifies a user account.
  
  - -aG is the option that tells the command to add the user to a specific group. 
   The -a option adds a user to the group without removing it from current groups. 
   The -G option states the group where to add the user.
  
  - sudo is the group we append to the above options. In this case, it is sudo, but it can be any other group.
  
  - username is the name of the user account you want to add to the sudo group.

# Configuring static IP and a Netmask in \30
  
  Source: https://www.cyberciti.biz/faq/add-configure-set-up-static-ip-address-on-debianlinux/.
  
  `ip -c link show` will show available ethernet network interfaces. Note down the name of the network.
  Look for the address of the network by using command `ip -c addr show <network>`.
  
  ❗ subnet calculator I used: https://www.calculator.net/ip-subnet-calculator.html
  
  Gateway value is found with `ipconfig getoption en0 router` on your MAC. 
  ❗ In my case it is 10.13.254.254.
  
  Task is to set VMs CIDR to be /30 so subnet mask has to be 255.255.255.252
  
  ❗ For my IP I choce 10.13.254.36 from the 64 different network addresses available.
  
  Now you have gathered all the values needed for the next step.
  You can change your chocen networks settings in `/etc/network/interface`. 
  ❗ In my case `enp0s3` to `auto`:
  
    # This file describes the network interfaces available on your system
    # and how to activate them. For more information, see interfaces(5).

    source /etc/network/interfaces.d/*

    # The loopback network interface
    auto lo
    iface lo inet loopback

    # The primary network interface
    auto enp0s3
    
  
  You need to create a configuration file for it: `sudo vim /etc/network/interface.d/<network>`.
  In the file you want to write the values you previously got:
  
    iface enp0s3 inet static
    address 10.13.254.36
    netmask 255.255.255.252
    gateway 10.13.254.254

  After saving your new settings, restart networking by using command: `sudo systemctl restart networking`.
  
# Changing SSH port

  To edit the SSH settings you can use command: `sudo vim /etc/ssh/sshd_config`

  On row number 15 there is `#Port 22` as a default.
  Uncomment it and change the port number according to your liking.
  
  ❗ I set my port to `9212`.

  Restart ssh service: `sudo service ssh restart`.

# SSH access with public keys and ROOT access

  If you don't have an existing SSH key yet you can run command: `ssh-keygen -t rsa`.

  Incase you have one already, you can run following command: `ssh-copy-id user@ip -p port`,
  to copy it from your machine to the target location.
  
  Also manually copying your key from `~/.ssh/id_rsa.pub` to the target location `~/.ssh/authrized_keys` works.

  Editing `/etc/ssh/sshd_config` to:
  
  Disabling direct root access.
  
    34 PermitRootLogin no
  
  Public Key Authentication.
  
    39 PubkeyAuthentication yes
  
  Location of valid keys.
  
    42 AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
  
  Instead of using password to login to the system we want to use our public key, so we disable password authentication.
  
    58 PasswordAuthentication no
  
  No empty passwords.
  
    59 PermitEmptyPasswords no
  
# Firewall
  
  Source: https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands.
  
  UFW stands for uncomplicated firewall, to install it `sudo apt-get install ufw`.
  
  Things to note! 💡
  
   - You can see the status of UFW and its allowed connections with a command: `sudo ufw status`.

   - Do not enable ufw, if you're using an SSH connection, before configuring it's settings. It might cause some trouble. :)
    
  To begin, you want to make sure our SSH connection to the VM stays open by allowing the connection to the port: 
  `sudo ufw allow <portnumber>/tcp`.
  
  You want to enable other connections aswell such as HTTP and HTTPS:
  `sudo ufw allow 80/tcp`, port 80 being HTTP.
  `sudo ufw allow 443`, 443 being HTTPS.
  
  Finally to enable firewall and changes made to it: `sudo ufw enable`.
  
# DoS protection
  
  sources: 
  https://pipo.blog/articles/20210915-fail2ban-apache-dos and 
  https://www.garron.me/en/go2linux/fail2ban-protect-web-server-http-dos-attack.html.
 
  Installing fail2ban: `sudo apt-get install fail2ban`.
  
  Making a configuration file: `sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`.
  
  Then you need to edit `/etc/fail2ban/jail.local` to change few settings in `[sshd]` and also to create a completely new jail `[http-get-dos]`.
  
    [sshd]

    # To use more aggressive sshd modes set filter parameter "mode" in jail.local:
    # normal (default), ddos, extra or aggressive (combines all).
    # See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
    mode   = normal
    enabled = true
    port    = 9212
    logpath = %(sshd_log)s
    backend = %(sshd_backend)s
    maxretry = 3
    bantime = 900

    # DoS protection
    [http-get-dos]
    enabled = true
    port = http,https
    filter = http-get-dos
    logpath = /var/log/apache2/access.log
    maxretry = 150
    findtime = 300
    bantime = 900
    action = iptables[name=HTTP, port=http, protocol=tcp]
  
  after saving the configuration you need to make a filter for your new jail:
  `sudo vim /etc/fail2ban/filter.d/http-get-dos.conf`.
  
  Useful tool to figure out a regex configuration: https://www.regextester.com.
  
    [Definition]
    failregex = ^<HOST> -.*(GET|POST).*
    ignoreregex =
  
  
  Save and restart fail2ban: `sudo systemctl restart fail2ban`.
  
  ❗ What I used to test my fail2ban: https://github.com/gkbrk/slowloris.
  
  `python3 slowloris.py 10.13.254.36 --sleeptime 1 -s 500`.
  
  to try and unban yourself: `sudo fail2ban-client unban http-get-dos <bannedip>`.
  
# Portscan protection
  
  Source: https://en-wiki.ikoula.com/en/To_protect_against_the_scan_of_ports_with_portsentry.
  
  Installing portsentry: `sudo apt-get install portsentry`.
  
  First you head to `/etc/default/portsentry` and set TCP and UDP modes to advanced:
  
    TCP_MODE="atcp"
    UDP_MODE="audp"
  
  What advanced mode does is portsentry will monitor for any ports below 1024 (by default),
  You can change the default values in `/etec/portsentry/portsentry.conf` on lines 61 and 62,
  but it's not recommended. (see `/etec/portsentry/portsentry.conf` lines 49-58).
  
  Then editing portsentrys configuration in `/etc/portsentry/portsentry.conf` line 113 onwards, you need to block UDP/TCP scans,
  by changing both number options from 0 ("Do not block UDP/TCP scans") to 1 ("Block UDP/TCP scans").
  
    BLOCK_UDP="1"
    BLOCK_TCP="1"
 
  I opt for a blocking of malicious persons through iptables. First I comment my current "KILL_ROUTE" and uncomment
  the line compatible with iptables: `KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"`.
  
  You can check that you only have 1 "KILL_ROUTE" active with a command: `cat /etc/portsentry/portsentry.conf | grep KILL_ROUTE | grep -v "#"`.
  
  Once everything is done, restart portsentry: `sudo systemctl restart portsentry`.
  
# Disable unused services

  To check all processes: 
  
    sudo systemctl list-units --type service --all
    
  To list enabled services: 

    sudo systemctl list-unit-files --state=enabled --type=service
    
  Disable every service not used in the project with:
  
    sudo systemctl disable <service>
    
# Script to update all the packages

  I created a folder to hold my scripts in `/usr/scripts/`.
  
  The script will be writing information to a log file located in `/var/log/auto_update.log` and will also update all packages on the machine.

    #!/bin/bash

    echo UPDATING PACKAGES >> /var/log/auto_update.log
    echo $(date) >> /var/log/auto_update.log
    sleep 5
    echo `sudo apt-get update --yes` >> /var/log/auto_update.log
    echo `sudo apt-get upgrade --yes` >> /var/log/auto_update.log
    echo '' >> /var/log/auto_update.log
    
  Remember to add executable rights to the script.
  
  To make this script run everytime you boot the machine and once a week at 4AM you can use crontab.
  
  Source: https://crontab-generator.org/.
  
  Run `sudo crontab -e` to edit your crontab file. In the file you need to add 2 things:
  
    # run auto_update.sh when reboting
    @reboot sh /usr/scripts/auto_update.sh

    # run auto_update.sh once a week at 4AM (Tuesday)
    0 4 * * 2 sh /usr/scripts/auto_update.sh

 Save and close the file, you can use `sudo crontab -l` to view your current crontab.
 
# Script to monitor crontab changes

  I created another script in `/usr/scripts/` called `monitor_crontab.sh`.

    #!/bin/sh

    CRONTAB='/var/spool/cron/crontabs/root'
    BACKUP='/var/spool/cron/crontabs/root.backup'

    DIFF=`diff $CRONTAB $BACKUP`
    if [ ! -z "$DIFF" ]; then
      echo "Changes in CRONTAB file." | mail -s "Crontab modifed" root
    fi

    cp $CRONTAB $BACKUP
    
  Remember to add executable rights to the script.
    
  It will send a notification to root if machines crontab file has been edited.
  
  To get started you need to install couple of packages:
  
  **Mailutils**
  
  `sudo apt-get install mailutils`.
  
  **Postfix**
  
  `sudo apt-get install postfix`.
  
  The configuration of postfix is located in `/etc/postfix/main.cf`, but you can also use postfixes own command `postconf` to query or configure settings directly.
  
  You want to edit your mailboxes location with a command `sudo postconf -e "home_mailbox = mail/"`.
  
  Restart postfix service with a command: `sudo service postfix restart`.
  
  **mutt**
  
  `sudo apt-get install mutt`.
  
  Create a configuration file in `/root/.muttrc` and add the following to it:
  
    set mbox_type=Maildir
    set folder="/root/mail"
    set mask="!^\\.[^.]"
    set mbox="/root/mail"
    set record="+.Sent"
    set postponed="+.Drafts"
    set spoolfile="/root/mail"
    
  Now you should be able to recive and send mail.
  
  Example: 
  
    echo "text' | sudo mail -s "subject" <reciver>
    
  You can open your mailbox with a command: `mutt`.


  To make the script run itself every day at 00:00, make a new crontab task with a command: `sudo crontab -e`.

    # run monitor_crontab.sh everyday at 00:00
    0 0 * * * sh /usr/scripts/monitor_crontab.sh
  
  You now have a working script auto executed by crontab.
  
  
# Web part
  
  You have the possibility go with either Nginx or Apache. 
  
  ❗ I chose to go with Apache.
  
  Installing Apache: `sudo apt update && sudo apt-get install apache2`.
  
  To check status of your webserver: `sudo systemctl status apache2`.
  
  Head over `/etc/apache2/ports.conf` and add your VMs IP:

    # If you just change the port or add more ports here, you will likely also
    # have to change the VirtualHost statement in
    # /etc/apache2/sites-enabled/000-default.conf

    Listen 10.13.254.36:80

    <IfModule ssl_module>
      Listen 10.13.254.36:443
    </IfModule>

    <IfModule mod_gnutls.c>
      Listen 10.13.254.36:443
    </IfModule>

  This configuration will prevent VM from listening to https://localhost and will work only using https://10.13.254.36. You can confirm this by
  installing curl `sudo apt install curl` and trying `curl -k https://localhost`. It should say `Connection refused`.
  
# SSL sertificate
  
  source: https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10.
  
  You can create a self-signed key and certificate pair with OpenSSL in a single command:
  `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt`.
  
  - openssl: This is the basic command line tool for creating and managing OpenSSL certificates, keys, and other files.
  req: This subcommand specifies that we want to use X.509 certificate signing request (CSR) management. The “X.509” is a public key infrastructure standard that SSL and TLS adheres to for its key and certificate management. We want to create a new X.509 cert, so we are using this subcommand.
  - x509: This further modifies the previous subcommand by telling the utility that we want to make a self-signed certificate instead of generating a certificate signing request, as would normally happen.
  - nodes: This tells OpenSSL to skip the option to secure our certificate with a passphrase. We need Apache to be able to read the file, without user intervention, when the server starts up. A passphrase would prevent this from happening because we would have to enter it after every restart.
  - days 365: This option sets the length of time that the certificate will be considered valid. We set it for one year here.
  - newkey rsa:2048: This specifies that we want to generate a new certificate and a new key at the same time. We did not create the key that is required to sign the certificate in a previous step, so we need to create it along with the certificate. The rsa:2048 portion tells it to make an RSA key that is 2048 bits long.
  - keyout: This line tells OpenSSL where to place the generated private key file that we are creating.
  - out: This tells OpenSSL where to place the certificate that we are creating.

  Answer the following questions..
  
  Create a new snippet in the `/etc/apache2/conf-available directory`. You will name the file `ssl-params.conf` to make its purpose clear:
  `sudo vim /etc/apache2/conf-available/ssl-params.conf`.
  
  Paste this in `ssl-params.conf`:
  
    SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
    SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder On
    # Disable preloading HSTS for now.  You can use the commented out header line that includes
    # the "preload" directive if you understand the implications.
    # Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    # Requires Apache >= 2.4
    SSLCompression off
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
    # Requires Apache >= 2.4.11
    SSLSessionTickets Off

  **Modifying the Default Apache SSL Virtual Host File**

  Before modifying the file take backup of the original SSL Virtual Host file:
  
  `sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak`.
  
  Then we edit our configuration file:
  
  `sudo vim /etc/apache2/sites-available/default-ssl.conf`.
   
  by default it looks like this:
  
    <IfModule mod_ssl.c>
      <VirtualHost _default_:443>
      ServerAdmin webmaster@localhost

      DocumentRoot /var/www/html

      ...

      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined

      ...

      SSLEngine on

      ...

      SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
      SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

      ...

      <FilesMatch "\.(cgi|shtml|phtml|php)$">
          SSLOptions +StdEnvVars
      </FilesMatch>
      <Directory /usr/lib/cgi-bin>
          SSLOptions +StdEnvVars
      </Directory>

      ...

    </VirtualHost>
  </IfModule>
  
  Change settings accordingly: 
  
    <IfModule mod_ssl.c>
      <VirtualHost _default_:443>
        ServerAdmin tlahin@student.hive.fi
        ServerName 10.13.254.36

        DocumentRoot /var/www/html

        ...

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        ...

        SSLEngine on

        ...

        SSLCertificateFile	/etc/ssl/certs/apache-selfsigned.crt
        SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key

        ...


      </VirtualHost>
    </IfModule>
  
    **Modifying the HTTP Host File to Redirect to HTTPS**
  
  `sudo vim /etc/apache2/sites-available/000-default.conf`.
  
      <VirtualHost *:80>
      ....

      Redirect "/" "https://10.13.254.36/"

      ...

      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined

      ...
    </VirtualHost>

  **Enabling the Changes in Apache**
  
  Enable mod_ssl (the Apache SSL module) and mod_headers, which is needed by some of the settings in our SSL snippet:
  
  `sudo a2enmod ssl` and `sudo a2enmod headers`.
  
  Next, enable your SSL Virtual Host with the a2ensite command:
  
  `sudo a2ensite default-ssl`.
  
  You will also need to enable your ssl-params.conf file, to read in the values you’ve set:
  
  `sudo a2enconf ssl-params`.
  
  At this point, the site and the necessary modules are enabled. You should check to make sure that there are no syntax errors in our files. Do this by typing:
  
  `sudo apache2ctl configtest`.
  
  As long as your output has `Syntax OK` everything is all setup. Now you can restart Apache to implement the changes: `sudo systemctl restart apache2`.
  
  **Testing Encryption**
  
  Open your web browser and type `http://server_domain_or_IP`.
  
  ![image](https://user-images.githubusercontent.com/79833061/172443709-3a12ac8d-4dd6-41af-8c58-8b2f003e86c1.png)

  Because the certificate you created isn’t signed by one of your browser’s trusted certificate authorities, you will likely see a scary looking warning.
  
  This is expected and normal. We are only interested in the encryption aspect of our certificate, not the third party validation of our host’s authenticity. Click ADVANCED and then the link provided to proceed to your host anyways.
  
  You should be taken to your site. If you look in the browser address bar, you will see a lock with an “x” over it or another similar “not secure” notice. In this case, this just means that the certificate cannot be validated. It is still encrypting your connection.
  
  ![image](https://user-images.githubusercontent.com/79833061/172444304-da238214-2398-4bd4-9334-d9818787ea99.png)

  
  If you configured Apache to redirect HTTP to HTTPS, you can also check whether the redirect functions correctly: `http://server_domain_or_IP`.
  
  Now you have configured your Apache server to use strong encryption for client connections. This will allow you to serve requests securely and will prevent outside parties from reading your traffic

# Deployment automatization script

  Created yet another script in `/usr/scripts/`. This script will check if theres new changes in `/usr/scripts/deployment/`, if so it will deploy the changes to `/var/www/html/` and log the action in `/var/log/auto_deployment.log`.

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
    
  Remember to add executable rights to the script.
  
  Add a new crontab job to run the script every day at 4AM: `sudo crontab -e`
  
    # run auto_deployment.sh everyday at 4AM
    0 4 * * * sh /usr/scripts/auto_deployment.sh
