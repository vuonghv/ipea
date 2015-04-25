# ipea
IP encryption and authentication protocol

To build the module, run:   $ make clean && make
To insert the module into the kernel, run:    $ make ipea_module.in
To remove module, run:    $ make ipea_module.rm
  
To test the module in your host, you can ping yours host's IP address and use 'dmesg' to read the kernel's log.
