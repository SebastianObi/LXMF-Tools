# lxmf_ping
This program sends an adjustable number of LXMF messages to a destination. Then a simple statistic is created to check the success or failure of a single message. This tool can be useful to load the LXMF/Reticulum network with a defined load of messages. This can be used to simulate a certain amount of users.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with all LXMF applications (NomadNet, Sideband, ...)


## Examples of use

### 

### General info how the messages are transported
All messages between client<->server are transported as single 1:1 messages in the LXMF/Reticulum network.
Accordingly, encryption takes place between these end points.
If a direct delivery of the message does not work, it is sent to a propagation node. There it is stored temporarily and can be retrieved by the client later.

As these are normal LXMF messages, any LXMF capable application can be used to communicate with the group.


## Current Status
It should currently be considered beta software. All core features are implemented and functioning, but additions will probably occur as real-world use is explored. There will be bugs.
The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Screenshots / Usage examples
<img src="../docs/screenshots/lxmf_ping_01.png" width="1000px">


## Installation manual

### Install:
- Install all required prerequisites. (Default Reticulum installation. Only necessary if reticulum is not yet installed.)
  ```bash
  apt update
  apt upgrade
  
  apt install python3-pip
  
  pip install pip --upgrade
  reboot
  
  pip3 install rns
  pip3 install pyserial netifaces
  
  pip3 install lxmf
  ```
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](lxmf_ping.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_ping/lxmf_ping.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x lxmf_ping.py
  ```

### Start:
- Start it
  ```bash
  ./lxmf_ping.py
  ```


### Startup parameters:
```bash
usage: lxmf_ping.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] -d DEST [-t TIME] [-s SIZE] [-c COUNT] [-i INST]

LXMF Ping - Periodically sends pings/messages and evaluates the status

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pr PATH_RNS, --path_rns PATH_RNS
                        Path to alternative Reticulum config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -d DEST, --dest DEST  Single destination hash or ,-separated list with destination hashs or . for random destination
  -t TIME, --time TIME  Time between messages in seconds
  -s SIZE, --size SIZE  Size (lenght) of the message content
  -c COUNT, --count COUNT
                        Maximum message send count (0=no end)
  -i INST, --inst INST  Parallel instances (different sender addresses)
```


## User manual
This guide applies to users or admins. Here are briefly explained the normal possibilities of the software.


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)