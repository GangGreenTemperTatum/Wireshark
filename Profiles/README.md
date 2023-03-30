# Instructions

To import these Wireshark profiles into your default Wireshark user profile directory:

1) Unzip the zipped directories to their own unique folder (I.E, `BGPDefault.zip` -> `BGPDefault`) 

I have written a [shell script (`enumerate_zipped_directories_to_unzipped_format.sh`) here](https://github.com/GangGreenTemperTatum/bash/blob/main/enumerate_zipped_directories_to_unzipped_format.sh) that can automate this for you.

2) Copy the unzipped directories contents to the default (example below:)
```
$ cp -R ./ /Users/GangGreenTemperTatum/.config/wireshark/profiles/
./ -> /Users/GangGreenTemperTatum/.config/wireshark/profiles
```
3) Gracefully restart Wireshark, voila!

# OR:

1) Copy the zipped Wireshark profiles into your default Wireshark user profile directory:
```
$ cp -R ./*.zip /Users/GangGreenTemperTatum/.config/wireshark/profiles/
```
2) Automate the uncompressing of zipped folders and their contents to their own unique directory [shell script (`enumerate_zipped_directories_to_unzipped_format.sh`) here](https://github.com/GangGreenTemperTatum/bash/blob/main/enumerate_zipped_directories_to_unzipped_format.sh)

OR:

`for i in `ls`; do unzip -d ./; done;`

3) Gracefully restart Wireshark, voila!
