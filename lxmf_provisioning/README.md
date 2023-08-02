# lxmf_provisioning
This program offers the possibility of provisioning clients. This includes, for example: The announcement of software updates. Registration of new users. Saving telemetry data that the clients send to the server. The data is stored in a PostgreSQL database. The source code can of course be customized to store the data in a different way.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with all Reticulum managed apps (Communicator)
- Announcement of the server and software versions
- User registration
- Collection of telemetry data
- Storage of data in PostgreSQL, ...


## Examples of use

### General info how the messages/data are transported
All announcements are transmitted unencrypted with their own type/name which is not shown in the Nomadnet/Sideband announcement list.
All messages between client<->server are transported as single 1:1 messages in the LXMF/Reticulum network.
Accordingly, encryption takes place between these end points.


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Screenshots / Usage examples


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
- Download the [file](lxmf_provisioning.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_provisioning/lxmf_provisioning.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x lxmf_provisioning.py
  ```

### Start:
- Start it
  ```bash
  ./lxmf_provisioning.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.lxmf_provisioning/config.cfg.owr
  ```
  ```bash
  [lxmf]
  announce_periodic = Yes
  announce_periodic_interval = 15 #Minutes
  
  [database]
  host = 127.0.0.1
  port = 5432
  user = postgres
  password = password
  database = test
  table_registration = tbl_account
  table_telemetry = tbl_telemetry
  
  [features]
  announce_versions = True
  registration = True
  telemetry = True
  
  [data]
  v_s = 0.1.4 #Version software
  v_c = 2022-11-29 20:00 #Version config
  v_d = 2022-11-29 20:00 #Version data
  v_a = 2022-11-29 20:00 #Version auth
  u_s = https:// #URL Software
  ```
- Start it again. Finished!
  ```bash
  ./lxmf_provisioning.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/lxmf_provisioning.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=LXMF Provisioning Daemon
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/lxmf_provisioning.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable lxmf_provisioning
  ```
- Start the service.
  ```bash
  systemctl start lxmf_provisioning
  ```


### Start/Stop service:
  ```bash
  systemctl start lxmf_provisioning
  systemctl stop lxmf_provisioning
  ```


### Enable/Disable service:
  ```bash
  systemctl enable lxmf_provisioning
  systemctl disable lxmf_provisioning
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./lxmf_provisioning.py -p /root/.lxmf_provisioning_2nd
  ./lxmf_provisioning.py -p /root/.lxmf_provisioning_3nd
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
- This provisioning server address must be added to the clients.
- Now the software can be used.


### Startup parameters:
```bash
usage: lxmf_provisioning.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride]

LXMF Provisioning Server -

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


### Standard function (Announce versions, user registration, telemetry):
- `config.cfg.owr`
  ```
  [lxmf]
  announce_periodic = Yes
  announce_periodic_interval = 15 #Minutes
  
  [database]
  host = 127.0.0.1
  port = 5432
  user = postgres
  password = password
  database = test
  table_registration = tbl_account
  table_telemetry = tbl_telemetry
  
  [features]
  announce_versions = True
  registration = True
  telemetry = True
  
  [data]
  v_s = 0.1.4 #Version software
  v_c = 2022-11-29 20:00 #Version config
  v_d = 2022-11-29 20:00 #Version data
  v_a = 2022-11-29 20:00 #Version auth
  u_s = https:// #URL Software
  ```


### Custom function (Announce versions):
- `config.cfg.owr`
  ```
  [lxmf]
  announce_periodic = Yes
  announce_periodic_interval = 15 #Minutes

  [features]
  announce_versions = True
  registration = False
  telemetry = False
  
  [data]
  v_s = 0.1.4 #Version software
  v_c = 2022-11-29 20:00 #Version config
  v_d = 2022-11-29 20:00 #Version data
  v_a = 2022-11-29 20:00 #Version auth
  u_s = https:// #URL Software
  ```


## Admin manual
This guide applies to all admins. Here are briefly explained the administative possibilities.


## User manual
This guide applies to users or admins. Here are briefly explained the normal possibilities of the software.


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)