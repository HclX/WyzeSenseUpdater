# WyzeSenseUpdater


To prepare the device, use the following command once:
```
sudo cp 99-wyze-usb-access.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

This tool can be used to flash or dump device content. For read, a couple
important regions:
* Flash:    addr = 0x00000000, count=0x20000
* ROM:      addr = 0x10000000, count=0x20000
* RAM:      addr = 0x20000000, count=0x5000
* CCFG:     addr = 0x50003000, count=0x1000
* FCFG:     addr = 0x50001000, count=0x3F0