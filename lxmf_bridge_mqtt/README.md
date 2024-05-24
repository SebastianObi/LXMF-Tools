# lxmf_bridge_mqtt
This program provides an interface between LXMF and MQTT. It serves as a single message endpoint and not to transfer the LXMF/Reticlum traffic 1:1 to MQTT. It serves the purpose of providing an endpoint in the Reticulum network for third party applications that can communicate via MQTT. Through this all LXMF capable applications can communicate with it via messages. This can be used for example to communicate via text messages with a smarthome system (FHEM, openHAB, ioBroker, Node-RED or similar). The transmission format used by MQTT is JSON with freely definable topics. The target system can then respond to these JSON messages.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with all LXMF applications (NomadNet, Sideband, ...)
- Compatible with all MQTT servers


## Examples of use

### 

### General info how the messages are transported
All messages between client<->server are transported as single 1:1 messages in the LXMF/Reticulum network.
Accordingly, encryption takes place between these end points.
If a direct delivery of the message does not work, it is sent to a propagation node. There it is stored temporarily and can be retrieved by the client later.

As these are normal LXMF messages, any LXMF capable application can be used to communicate with it.


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Screenshots / Usage examples
<img src="../docs/screenshots/lxmf_bridge_mqtt_01.png" width="200px">


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
- Install all required prerequisites.
  ```bash
  pip3 install paho-mqtt
  ```
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](lxmf_bridge_mqtt.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_bridge_mqtt/lxmf_bridge_mqtt.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x lxmf_bridge_mqtt.py
  ```

### Start:
- Start it
  ```bash
  ./lxmf_bridge_mqtt.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.lxmf_bridge_mqtt/config.cfg.owr
  ```
  ```bash
  ```
- Start it again. Finished!
  ```bash
  ./lxmf_bridge_mqtt.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/lxmf_bridge_mqtt.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=LXMF Bridge MQTT Daemon
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/lxmf_bridge_mqtt.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable lxmf_bridge_mqtt
  ```
- Start the service.
  ```bash
  systemctl start lxmf_bridge_mqtt
  ```


### Start/Stop service:
  ```bash
  systemctl start lxmf_bridge_mqtt
  systemctl stop lxmf_bridge_mqtt
  ```


### Enable/Disable service:
  ```bash
  systemctl enable lxmf_bridge_mqtt
  systemctl disable lxmf_bridge_mqtt
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./lxmf_bridge_mqtt.py -p /root/.lxmf_bridge_mqtt_2nd
  ./lxmf_bridge_mqtt.py -p /root/.lxmf_bridge_mqtt_3nd
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.


### First usage:
- With a manual start via the console, the own LXMF address is displayed:
  ```
  [] ...............................................................................
  [] LXMF - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- This address is also annouced at startup in the default setting.
- Now the software can be used.


### Startup parameters:
```bash
usage: lxmf_bridge_mqtt.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig]
                                  [--exampleconfigoverride]

LXMF Bridge MQTT

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pr PATH_RNS, --path_rns PATH_RNS
                        Path to alternative Reticulum config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Running as a service and should log to file
  --exampleconfig       Print verbose configuration example to stdout and exit
  --exampleconfigoverride
                        Print verbose configuration example to stdout and exit
```


### Config/data files:
- config.cfg
  
  This is the default config file.

- config.cfg.owr
  
  This is the user configuration file to override the default configuration file.
  All settings made here have precedence.
  This file can be used to clearly summarize all settings that deviate from the default.
  This also has the advantage that all changed settings can be kept when updating the program.


## Configuration manual (Examples)
The configurations shown here are only a part of the total configuration.
It only serves to show the configuration that is necessary and adapted for the respective function.
All configurations must be made in the file `config.cfg.owr`.
All possible settings can be seen in the default configuration file `config.cfg`.


## Admin manual
This guide applies to all admins. Here are briefly explained the administative possibilities.


## User manual
This guide applies to users or admins. Here are briefly explained the normal possibilities of the software.


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)