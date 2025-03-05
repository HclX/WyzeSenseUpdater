# WyzeSenseUpdater

## Prepare
To prepare the device, use the following command once to give you write access
without root user:
```
sudo cp 99-wyze-usb-access.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Creating flash dump
This tool can be used to flash or dump the wyze sense USB bridge device. To get
firmware dump, run:
```
./ws_updater.py dump -o <output>
```
By default, the output will be stored in file `dump.bin`.

## Flashing the latest HMS firmware
To flash the bridge device to latest HMS firmware, use the following command:
```
./ws_updater.py flash --input firmwares/flash_gw3u_47.bin
```

Flashing is done by first erasing the flash content, and then writing the
new content. Unfortunately, one critical region which controls the firmware
update mode will also be erased. So there is a possibility that the device
will be bricked if anything goes wrong. It's always a good idea to backup the
firmware using `dump` command before flashing.

If `flash` command fails, do NOT unplug the device. You might still be able to
recover by flashing the `dump.bin` file, but this is not guaranteed working.

## Other functions
This tool can also be used to read other memory regions, here are a couple
important ones:
* Flash:    addr = 0x00000000, count=0x20000
* ROM:      addr = 0x10000000, count=0x20000
* RAM:      addr = 0x20000000, count=0x5000
* CCFG:     addr = 0x50003000, count=0x1000
* FCFG:     addr = 0x50001000, count=0x3F0

## Firmware dumps
There are other firmware dumps under `firmwares` directory for research
purposes, do NOT flash any of them unless you know what you are doing.

