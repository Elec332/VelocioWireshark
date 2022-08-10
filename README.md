# VelocioWireshark

Just copy the lua file in your wireshark plugins folder to use it.
To ensure the course coloring still works, is exposes all USB BULK data as usb.capdata, just as wireshark would if no dissector was present.

In order to filter by only velocio traffing and exclude the debug spam, use `(velocio) && !(velocio.cmd == 0x10)`
