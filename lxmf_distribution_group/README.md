# lxmf_distribution_group
This program provides an email like distribution group for the "Communicator" app. Which is another project that is not part of this github. It will distribute incoming LXMF messages to multiple recipients.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with (Communicator which is another project that is not part of this github)
- Server/Node based message routing and processing
- Direct or propagated message delivery (receive/send)
- Simple group functions (As in other messenger apps)
- User authorization and permissions
- Different user types with different permissions
- Automatic or manual group joining
- Easy configuration within readable config files
- Multiple language support (English & German are predifined)


## Examples of use

### Local self-sufficient group
In a small group of people, this group software can be hosted on a centrally located node. This then allows users to communicate with each other via this group.

### Multiple local self-sufficient group
On the same node/server several groups can be operated independently of each other. How this works is described below in the installation instructions.

### General info how the messages are transported
All messages between client<->group-server are transported as single 1:1 messages in the LXMF/Reticulum network.
Accordingly, encryption takes place between these end points.
If a direct delivery of the message does not work, it is sent to a propagation node. There it is stored temporarily and can be retrieved by the client later.

There is no central server for communication between the individual groups. This offers the advantage that all groups work autonomously. A failure of a group only affects this one local group. 


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Development Roadmap
- Planned, but not yet scheduled
  - Complete documentation


## Screenshots / Usage examples
<img src="../docs/screenshots/lxmf_distribution_group_01.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_02.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_03.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_04.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_05.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_06.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_07.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_08.png" width="200px">


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
  
  # Set propagation node automatically.
  propagation_node_auto = True
  
  # Try to deliver a message via the LXMF propagation network,
  # if a direct delivery to the recipient is not possible.
  try_propagation_on_fail = Yes
  
  
  #### Telemetry settings ####
  [telemetry]
  location_enabled = False
  location_lat = 0
  location_lon = 0
  
  state_enabled = False
  state_data = 0
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


### First usage:
- With a manual start via the console, the own group LXMF address is displayed:
  ```
  [] ...............................................................................
  [] LXMF - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- This address is also annouced at startup in the default setting.
- If auto add user is active (default) you can simply send a first message via Sideband/NomadNet to this address. After that you are a member of the group and can use the functions.
- Alternatively, the users can also be entered manually in the `data.cfg` file. It is necessary to add an admin user here to use all commands via LXMF messages!
- Now the group can be used.


### Startup parameters:
```bash
usage: lxmf_distribution_group.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride] [--exampledata]

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
  
  This is the data file. It is automatically created and saved/overwritten.
  It contains data managed by the software itself.
  If manual adjustments are made here, the program must be shut down first!


## Configuration manual (Examples)
The configurations shown here are only a part of the total configuration.
It only serves to show the configuration that is necessary and adapted for the respective function.
All configurations must be made in the file `config.cfg.owr`.
All possible settings can be seen in the default configuration file `config.cfg`.


### Announcement of the group:
- `config.cfg.owr`
  ```
  [lxmf]
  announce_startup = Yes
  announce_startup_delay = 0 #Seconds
  announce_periodic = Yes
  announce_periodic_interval = 120 #Minutes
  ```


### Message propagation - Send:
- `config.cfg.owr`
  ```
  [lxmf]
  desired_method = direct #direct/propagated
  propagation_node = ca2762fe5283873719aececfb9e18835
  propagation_node_auto = True
  try_propagation_on_fail = Yes
  ```


### Message propagation - Receive (Sync from node):
- `config.cfg.owr`
  ```
  [lxmf]
  propagation_node = ca2762fe5283873719aececfb9e18835
  propagation_node_auto = True
  sync_startup = Yes
  sync_startup_delay = 30 #Seconds
  sync_periodic = Yes
  sync_periodic_interval = 30 #Minutes
  sync_limit = 8
  ```


## Admin manual
This guide applies to all admins. Here are briefly explained the administative possibilities.

An administartor has correspondingly higher permissions and more commands are available. In general, the permissions can be freely defined. All users/admins etc. can also generally have the same permissions.


## User manual
This guide applies to users or admins. Here are briefly explained the normal possibilities of the software.


### Start/Join the group:
Just send a first message to the group address with Sideband/NomadNet.
However, this is only possible if automatic joining of the group is activated.


## FAQ

### Why this server based group function and no direct groups in the client software?
At the time of the development of these group functions there is no other possibility to use groups via Sideband/Nomadnet. Therefore this software was developed as a workaround.
This software also offers other functions than a normal group broadcast.

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)