# Roger_skyline_1


This subject aims to initiate you to the basics of system and network administration.

We are going to be installing a Virtual Machine and deploying a simple website.

# Installing Virtual Machine
  
  I chose to install Debian since I used it in INIT aswell.
  
  First task was to set 8 GB of disk size to the VM and atleast one partition to be 4.2 GB
  
  Easily configured during the graphical installation of Debian.
  You're able to check the size of the partitions with a command: `sudo fdisk -l`.
 
# Adding rights to sudo

   `usermod -aG sudo username`.
  
   - usermod is the tool that modifies a user account.
  
   - -aG is the option that tells the command to add the user to a specific group. 
   The -a option adds a user to the group without removing it from current groups. 
   The -G option states the group where to add the user.
  
   - sudo is the group we append to the above options. In this case, it is sudo, but it can be any other group.
  
   - username is the name of the user account you want to add to the sudo group.

# Configuring static IP and a Netmask in \30
  
  Source: https://www.cyberciti.biz/faq/add-configure-set-up-static-ip-address-on-debianlinux/.
  
  `ip -c link show` will show available ethernet network interfaces. Note down the name of the <network>.
  Look for the address of the network by using command `ip -c addr show <network>`.
  
  subnet calculator I used: https://www.calculator.net/ip-subnet-calculator.html
  
  Gateway value is found with `ipconfig getoption en0 router` on your MAC.
  In my case it is 10.13.254.254.
  
  Since we want our CIDR to be /30 our subnet mask has to be 255.255.255.252
  
  For my IP I choce 10.13.254.32 from the 64 different network addresses available.
  
  Now we have all the values we need.
  We change our chocen networks settings in `/etc/network/interface`, in my case `enp0s3` to `auto`:
  
  ![image](https://user-images.githubusercontent.com/79833061/171835158-2ae72f6a-ec43-4fe8-8da1-43a678fcea91.png).
  
  Then we want to create a configuration file for it: `sudo vim /etc/network/interface.d/<network>`.
  In the file we want to write the values we just gathered:
  
  ![image](https://user-images.githubusercontent.com/79833061/171835962-865c86f7-58ef-42fd-b22b-4598bff73960.png).

  After saving your new settings, restart networking by using command: `sudo systemctl restart networking`.
  
# Changing SSH ports

  To edit the SSH settings we use command: `sudo vim /etc/ssh/sshd_config`

  On row number 15 there is `#Port 22` as a default.
  Uncomment it and change the port number according to your liking.
  
  I set my port to `9212`.

  Restart ssh service: `sudo service ssh restart`.

# SSH access with public keys and ROOT access

  If you don't have an existing SSH key yet you can run command: `ssh-keygen -t rsa`.

  Incase you have one already, you can run following command: `ssh-copy-id user@ip -p port`,
  to copy it from your machine to the target location.
  
  Also manually copying your key from `~/.ssh/id_rsa.pub` to the target location `~/.ssh/authrized_keys` works.

  Editing `/etc/ssh/sshd_config` to:
  
  Disabling direct root access.
  
    `34 PermitRootLogin no`
  
  Public Key Authentication.
  
    `39 PubkeyAuthentication yes`
  
  Location of valid keys.
  
    `42 AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2`
  
  Instead of using password to login to the system we want to use our public key, so we disable password authentication.
  
    `58 PasswordAuthentication no`
  
  No empty passwords.
  
    `59 PermitEmptyPasswords no`
  
# Firewall
  
  Source: https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands.
  
  UFW stands for uncomplicated firewall, to install it `sudo apt-get install ufw`.
  
  Things to note! 💡
  
   - You can see the status of UFW and its allowed connections with a command: `sudo ufw status`.

   - Do not enable ufw, if you're using an SSH connection, before configuring it's settings. It might cause some trouble. :)
    
  To begin, we want to make sure our SSH connection to the VM stays open by allowing the connection to the port: 
  `sudo ufw allow <portnumber>/tcp`.
  
  We want to enable other connections aswell such as HTTP and HTTPS:
  `sudo ufw allow 80/tcp`, port 80 being HTTP.
  `sudo ufw allow 443`, 443 being HTTPS.
  
# DoS protection
  
  sources: 
  https://pipo.blog/articles/20210915-fail2ban-apache-dos and 
  https://www.garron.me/en/go2linux/fail2ban-protect-web-server-http-dos-attack.html.
 
  Installing fail2ban: `sudo apt-get install fail2ban`.
  
  Making a configuration file: `sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`.
  
  Then we need to edit `/etc/fail2ban/jail.local` and add few things:
  
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
    maxretry = retry
    findtime = 300
    bantime = 900
    action = iptables[name=HTTP, port=http, protocol=tcp]
  
  after saving the configuration we need to make a filter for it:
  `sudo vim /etc/fail2ban/filter.d/https-get-dos.conf`.
  
    [Definition]
    failregex = ^<HOST> -.*(GET|POST).*
    ignoreregex =
  
  Save and restart fail2ban: `sudo systemctl restart fail2ban`.
  
# Portscan protection
  
  Source: https://en-wiki.ikoula.com/en/To_protect_against_the_scan_of_ports_with_portsentry.
  
  Installing portsentry: `sudo apt-get install portsentry`.
  
  First we head to `/etc/default/portsentry` and set out TCP and UDP modes to advanced:
  
    9  TCP_MODE="atcp"
    10 UDP_MODE="audp"
  
  What advanced mode does is portsentry will monitor for any ports below 1024 (by default),
  You can change the default values in `/etec/portsentry/portsentry.conf` on lines 61 and 62,
  but it's not recommended. (see `/etec/portsentry/portsentry.conf` lines 49-58).
  
  Then editing portsentrys configuration in `/etc/portsentry/portsentry.conf` line 113 onwards, we block UDP/TCP scans,
  by changing both number options from 0 ("Do not block UDP/TCP scans") to 1 ("Block UDP/TCP scans").
  
    BLOCK_UDP="1"
    BLOCK_TCP="1"
 
  We opt for a blocking of malicious persons through iptables. First we comment our current "KILL_ROUTE" and uncomment
  the line compatible with iptables: `KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"`.
  
  You can check that you only have 1 "KILL_ROUTE" active with a command: `cat /etc/portsentry/portsentry.conf | grep KILL_ROUTE | grep -v "#"`.
  
  Once everything is done, restart portsentry: `sudo systemctl restart portsentry`.
  
  // HOW TO TEST IT?????
  
# Disable unused services
  
# Web part
  
  You were able go with either Nginx or Apache. I chose to go with Apache.
  
  Installing Apache: `sudo apt update && sudo apt-get install apache2`.
  
  To check status of your webserver: `sudo systemctl status apache2`.
  
  Head over `/etc/apache2/ports.conf` and add your VMs IP:
  
  ![image](https://user-images.githubusercontent.com/79833061/172383597-76ff3240-12d8-4b8b-aa9e-5ad4aa2f0c14.png)

  This configuration will prevent VM from listening to https://localhost and will work only using https://10.13.254.32. You can confirm this by
  installing curl `sudo apt install curl` and trying `curl -k https://localhost`. It should say `Connection refused`.
  
# SSL sertificate
  
  source: https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10.
  
  We can create a self-signed key and certificate pair with OpenSSL in a single command:
  `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt`.
  
  - openssl: This is the basic command line tool for creating and managing OpenSSL certificates, keys, and other files.
  req: This subcommand specifies that we want to use X.509 certificate signing request (CSR) management. The “X.509” is a public key infrastructure standard that SSL and TLS adheres to for its key and certificate management. We want to create a new X.509 cert, so we are using this subcommand.
  - x509: This further modifies the previous subcommand by telling the utility that we want to make a self-signed certificate instead of generating a certificate signing request, as would normally happen.
  - nodes: This tells OpenSSL to skip the option to secure our certificate with a passphrase. We need Apache to be able to read the file, without user intervention, when the server starts up. A passphrase would prevent this from happening because we would have to enter it after every restart.
  - days 365: This option sets the length of time that the certificate will be considered valid. We set it for one year here.
  - newkey rsa:2048: This specifies that we want to generate a new certificate and a new key at the same time. We did not create the key that is required to sign the certificate in a previous step, so we need to create it along with the certificate. The rsa:2048 portion tells it to make an RSA key that is 2048 bits long.
  - keyout: This line tells OpenSSL where to place the generated private key file that we are creating.
  - out: This tells OpenSSL where to place the certificate that we are creating.

  Answer the following question..
  
  Create a new snippet in the `/etc/apache2/conf-available directory`. We will name the file `ssl-params.conf` to make its purpose clear:
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

  Modifying the Default Apache SSL Virtual Host File

  Before modifying the file take backup of the original SSL Virtual Host file:
  
  `sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak`.
