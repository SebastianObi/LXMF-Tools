# LXMF-Tools
Various small programs and tools which use the message protocol LXMF from https://github.com/markqvist/LXMF


## lxmf_bridge_matrix
For more information, see the detailed [README.md](lxmf_bridge_matrix).


## lxmf_bridge_meshtastic
For more information, see the detailed [README.md](lxmf_bridge_meshtastic).


## lxmf_bridge_mqtt
This program provides an interface between LXMF and MQTT. It serves as a single message endpoint and not to transfer the LXMF/Reticlum traffic 1:1 to MQTT. It serves the purpose of providing an endpoint in the Reticulum network for third party applications that can communicate via MQTT. Through this all LXMF capable applications can communicate with it via messages. This can be used for example to communicate via text messages with a smarthome system (FHEM, openHAB, ioBroker, Node-RED or similar). The transmission format used by MQTT is JSON with freely definable topics. The target system can then respond to these JSON messages.

For more information, see the detailed [README.md](lxmf_bridge_mqtt).


## lxmf_bridge_telegram
For more information, see the detailed [README.md](lxmf_bridge_telegram).


## lxmf_chatbot
This program provides a simple chatbot (RiveScript) which can communicate via LXMF.

For more information, see the detailed [README.md](lxmf_chatbot).


## lxmf_cmd
This program executes any text received by message as a system command and returns the output of the command as a message. Only single commands can be executed directly. No interactive terminal is created.

For more information, see the detailed [README.md](lxmf_cmd).


## lxmf_distribution_group_extended
This program provides an email like distribution group. It will distribute incoming LXMF messages to multiple recipients. Since this program acts as a normal LXMF endpoint, all compatible chat applications can be used. In addition to simple messaging, there is a simple command-based user interface. Where all relevant actions for daily administration can be performed. The basic configuration is done in the configuration files. There are various options to adapt the entire behavior of the group to personal needs. This distribution group is much more than a standard email distribution group. It emulates advanced group functions with automatic notifications etc. Different user permissions can be defined. For each user type, the range of functions can be defined individually. The normal users have only small rights. While a moderator or admin can perform everything necessary by simple commands. Once the basic configuration is done, everything else can be done by LXMF messages as commands.

For more information, see the detailed [README.md](lxmf_distribution_group_extended).


## lxmf_distribution_group_minimal
This program is a minimalist version of the normal distribution group. The functionality is reduced to a minimum. Only sender and receiver users can be defined. Messages are then sent to the other users accordingly. There is no user interface or other notifications. Only the messages are distributed 1:1. The administration is done completely by the respective configuration files which are to be edited accordingly.

For more information, see the detailed [README.md](lxmf_distribution_group_minimal).


## lxmf_echo
This program is a simple echo server. All received messages are sent back 1:1 as an answer. This can be used as a simple counterpart to test the chat functionality of applications.

For more information, see the detailed [README.md](lxmf_echo).


## lxmf_propagation
For more information, see the detailed [README.md](lxmf_propagation).


## lxmf_terminal
This program provides a complete terminal session on the server. Any commands can be executed on the target device. The communication is done by single LXMF messages. This offers the advantage that simple terminal commands can be used by any LXMF capable application.

For more information, see the detailed [README.md](lxmf_terminal).


## lxmf_test
This program sends an adjustable number of LXMF messages to a destination. Then a simple statistic is created to check the success or failure of a single message. This tool can be useful to load the LXMF/Reticulum network with a defined load of messages. This can be used to simulate a certain amount of users.

For more information, see the detailed [README.md](lxmf_test).


## lxmf_welcome
This program sends an LXMF welcome message to all new peers who have been announced on the network.

For more information, see the detailed [README.md](lxmf_welcome).


## General Information for all tools/programs


### Current Status:
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


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

- Download the [file](lxmf_distribution_group.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_distribution_group/lxmf_distribution_group.py
  ```

- Make it executable with the following command
  ```bash
  chmod +x lxmf_distribution_group.py
  ```

### Start:
- Start it
  ```bash
  ./lxmf_distribution_group.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.lxmf_distribution_group/config.cfg.owr
  ```
- Start it again. Finished!
  ```bash
  ./lxmf_distribution_group.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/lxmf_distribution_group.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=lxmf_distribution_group
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/lxmf_distribution_group.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable lxmf_distribution_group
  ```
- Start the service.
  ```bash
  systemctl start lxmf_distribution_group
  ```


### Start/Stop service:
  ```bash
  systemctl start lxmf_distribution_group
  systemctl stop lxmf_distribution_group
  ```


### Enable/Disable service:
  ```bash
  systemctl enable lxmf_distribution_group
  systemctl disable lxmf_distribution_group
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./lxmf_distribution_group.py -p /root/.lxmf_distribution_group_2nd
  ./lxmf_distribution_group.py -p /root/.lxmf_distribution_group_3nd
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.


## Support / Donations
You can help support the continued development by donating via one of the following channels:

- PayPal: https://paypal.me/SebastianObi
- Liberapay: https://liberapay.com/SebastianObi/donate


## Support in another way?
You are welcome to participate in the development. Just create a pull request. Or just contact me for further clarifications.


## Do you need a special function or customization?
Then feel free to contact me. Customizations or tools developed specifically for you can be realized.


## FAQ
