# Edit Wireshark Global Configuration Profiles Folder Contents to .zip for GH Upload
#!/usr/local/bin/bash

for i in $(ls)
do
        zip -r $i.zip $i
        echo "Zipped Folder: $i"
done
