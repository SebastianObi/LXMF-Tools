# lxmf_distribution_group_minimal
This program is a minimalist version of the normal distribution group. The functionality is reduced to a minimum. Only sender and receiver users can be defined. Messages are then sent to the other users accordingly. There is no user interface or other notifications. Only the messages are distributed 1:1. The administration is done completely by the respective configuration files which are to be edited accordingly.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with all LXMF applications (Communicator, NomadNet, Sideband, ...)
- Server/Node based message routing and processing
- Direct or propagated message delivery (receive/send)
- Easy distribution of incoming messages to recipients


## Examples of use

### Local self-sufficient group
In a small group of people, this group software can be hosted on a centrally located node. This then allows users to communicate with each other via this group.

### Multiple local self-sufficient group
On the same node/server several groups can be operated independently of each other. How this works is described below in the installation instructions.

### General info how the messages are transported
All messages between client<->group-server are transported as single 1:1 messages in the LXMF/Reticulum network.
Accordingly, encryption takes place between these end points.
If a direct delivery of the message does not work, it is sent to a propagation node. There it is stored temporarily and can be retrieved by the client later.

As these are normal LXMF messages, any LXMF capable application can be used to communicate with the group.


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Screenshots / Usage examples
<img src="../docs/screenshots/lxmf_distribution_group_minimal_01.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_minimal_02.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_minimal_03.png" width="200px">


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
- Download the [file](lxmf_distribution_group_minimal.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_distribution_group_minimal/lxmf_distribution_group_minimal.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x lxmf_distribution_group_minimal.py
  ```

### Start:
- Start it
  ```bash
  ./lxmf_distribution_group_minimal.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.lxmf_distribution_group_minimal/config.cfg.owr
  ```
  ```bash
  # This is the user configuration file to override the default configuration file.
  # All settings made here have precedence.
  # This file can be used to clearly summarize all settings that deviate from the default.
  # This also has the advantage that all changed settings can be kept when updating the program.
  
  #### LXMF connection settings ####
  [lxmf]
  
  # The name will be visible to other peers
  # on the network, and included in announces.
  # It is also used in the group description/info.
  display_name = Distribution Group
  
  # Propagation node address/hash.
  propagation_node = ca2762fe5283873719aececfb9e18835
  
  # Set propagation node automatically.
  propagation_node_auto = True
  
  # Try to deliver a message via the LXMF propagation network,
  # if a direct delivery to the recipient is not possible.
  try_propagation_on_fail = Yes
  ```
- Start it again. Finished!
  ```bash
  ./lxmf_distribution_group_minimal.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/lxmf_distribution_group_minimal.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=lxmf_distribution_group_minimal.py Daemon
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/lxmf_distribution_group_minimal.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable lxmf_distribution_group_minimal
  ```
- Start the service.
  ```bash
  systemctl start lxmf_distribution_group_minimal
  ```


### Start/Stop service:
  ```bash
  systemctl start lxmf_distribution_group_minimal
  systemctl stop lxmf_distribution_group_minimal
  ```


### Enable/Disable service:
  ```bash
  systemctl enable lxmf_distribution_group_minimal
  systemctl disable lxmf_distribution_group_minimal
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./lxmf_distribution_group_minimal.py -p /root/.lxmf_distribution_group_minimal_2nd
  ./lxmf_distribution_group_minimal.py -p /root/.lxmf_distribution_group_minimal_3nd
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.


### First usage:
- With a manual start via the console, the own group LXMF address is displayed:
  ```
  [] ...............................................................................
  [] LXMF - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- This address is also annouced at startup in the default setting.
- The users need to be entered manually in the `data.cfg` file.
- Now the group can be used.


### Startup parameters:
```bash
usage: lxmf_distribution_group_minimal.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride] [--exampledata]

LXMF Distribution Group - Server-Side group functions for LXMF based apps

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
  --exampledata         Print verbose configuration example to stdout and exit
```


### Config/data files:
- config.cfg
  
  This is the default config file.

- config.cfg.owr
  
  This is the user configuration file to override the default configuration file.
  All settings made here have precedence.
  This file can be used to clearly summarize all settings that deviate from the default.
  This also has the advantage that all changed settings can be kept when updating the program.

- data.cfg
  
  This is the data file.
  It contains the user data.


## Configuration manual (Examples)
The configurations shown here are only a part of the total configuration.
It only serves to show the configuration that is necessary and adapted for the respective function.
All configurations must be made in the file `config.cfg.owr`.
All possible settings can be seen in the default configuration file `config.cfg`.


### Members:
All data here (`data.cfg`) contains the end users. The users must be maintained manually. There is no automatic joining to the group.
Please do not forget to restart the program after a modification!

- Receive only and send only members `data.cfg`
  ```
  [send]
  04652a820cc69d47940ce39050c455a6 = Test user with send only right 1
  
  [receive]
  d1b551e1b89fff5a4a6f2aaff2464971 = Test user with receive only right 1
  801f48d54bc71cb3e0886944832aaf8d = Test user with receive only right 2
  
  [receive_send]
    ```

- Receive and send members (Anyone can communicate with anyone)`data.cfg`
  ```
  [send]
  
  [receive]
  
  [receive_send]
  04652a820cc69d47940ce39050c455a6 = Test user 1
  d1b551e1b89fff5a4a6f2aaff2464971 = Test user 2
  801f48d54bc71cb3e0886944832aaf8d = Test user 3
    ```


## Admin manual
This guide applies to all admins. Here are briefly explained the administative possibilities.

### Manage users:
All users are maintained directly in the `data.cfg` file.
There is no automatic joining to the group.
Please do not forget to restart the program after a modification!

  ```
  # This is the data file. It is automatically created and saved/overwritten.
  # It contains data managed by the software itself.
  # If manual adjustments are made here, the program must be shut down first!
  
  
  #### User with send only rights ####
  [send]
  04652a820cc69d47940ce39050c455a6 = Test user 1
  
  #### User with receive only rights ####
  [receive]
  d1b551e1b89fff5a4a6f2aaff2464971 = Test user 2
  
  #### User with receive and send rights ####
  [receive_send]
  801f48d54bc71cb3e0886944832aaf8d = Test user 3
  ```


## User manual
This guide applies to users or admins. Here are briefly explained the normal possibilities of the software.


### Start/Join the group:
The administrator must create new users manually.


### Send message:
Any text will be interpreted as a normal message and sent to all members accordingly. There is nothing else to consider here.


## FAQ

### Why this server based group function and no direct groups in the client software?
At the time of the development of these group functions there is no other possibility to use groups via Sideband/Nomadnet. Therefore this software was developed as a workaround.
This software also offers other functions than a normal group broadcast.

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)