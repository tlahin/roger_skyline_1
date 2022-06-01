# roger_skyline_1


This subject aims to initiate you to the basics of system and network administration.

!!!! what to do we do in the project

# Installing Virtual Machine
  
  I choce Debian since I used it in INIT aswell.
  
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
  
  An amazing guide: https://www.cyberciti.biz/faq/add-configure-set-up-static-ip-address-on-debianlinux/
  
  `ip -c link show` will show available ethernet network interfaces.
  Look for the address of the network by using command `ip -c addr show nameoftheinterface`.
  
  subnet calculator I used: https://www.calculator.net/ip-subnet-calculator.html
  
  Gateway value is found with `ipconfig getoption en0 router` on your MAC.
  In my case it is 10.13.254.254.
  
  Since we want our CIDR to be /30 our subnet mask has to be 255.255.255.252
  
  For my IP I choce 10.13.254.32 from the 64 different network addresses.
  
  Now we have all the values we need. Using `sudo vim /etc/network/interface` to edit the configuration file, 
  we change our chosen networks settings.

  example:
  
  Original 
  ![image](https://user-images.githubusercontent.com/79833061/171382187-f7d31b32-94f0-49f8-88b0-5487abf3b7ba.png)

  
  New settings we just figured out
  ![image](https://user-images.githubusercontent.com/79833061/171382140-377f25f5-3fc8-4461-93ec-dc76bd1aed3e.png)
  
  After saving your new settings, restart networking by using command: `sudo systemctl restart networking`.
  
# Changing SSH ports

To edit the SSH settings we use command: `sudo vim /etc/ssh/sshd_config`

On row number 15 there is `#Port 22` as a default.
Uncomment it and change the port number according to your liking.

Restart ssh service: `sudo service ssh restart`.

# SSH access with public keys and ROOT access

  If you don't have an existing SSH key yet you can run command: `ssh-keygen -t rsa`.

  Incase you have one already, you can run following command: `ssh-copy-id user@ip -p port`,
  to copy it from your machine to the target location.
  
  Also manually copying your key from `~/.ssh/id_rsa.pub` to the target location `~/.ssh/authrized_keys` works.

# Setup a Firewall

# Set a DoS protection

Protecting against port scans

Disable unnecessary services

A script that updates all the packages

Monitor crontab changes

Web Part

Creating a self-signed SSL

Testing DoS with slowloris attack to Apache server

Deployment script
