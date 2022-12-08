# lxmf_provisioning
Dieses Programm bietet die Möglichkeit, Clients zu provisionieren. Dazu gehört zum Beispiel: Die Ankündigung von Software-Updates. Die Registrierung neuer Benutzer. Die Speicherung von Telemetriedaten, die die Clients an den Server senden. Die Daten werden in einer PostgreSQL-Datenbank gespeichert. Der Quellcode kann natürlich angepasst werden, um die Daten auf eine andere Weise zu speichern.

Weitere Informationen finden Sie in den Konfigurationsoptionen (am Ende der Programmdateien). Alles Weitere ist dort kurz dokumentiert. Nach dem ersten Start wird diese Konfiguration als Standardkonfiguration in der entsprechenden Datei angelegt.



### Eigenschaften
- Ankündigung der Server- und Softwareversionen
- Registrierung der Benutzer
- Sammlung von Telemetriedaten
- Speicherung der Daten in PostgreSQL, ...


## Beispiele für die Verwendung

### Allgemeine Informationen, wie die Nachrichten/Daten transportiert werden
Alle Ansagen werden unverschlüsselt mit ihrem eigenen Typ/Namen übertragen, der nicht in der Nomadnet/Sideband-Ansagenliste angezeigt wird.
Alle Nachrichten zwischen Client<->Server werden als einzelne 1:1 Nachrichten im LXMF/Reticulum Netzwerk transportiert.
Dementsprechend findet zwischen diesen Endpunkten eine Verschlüsselung statt.


## Aktueller Status
Es handelt sich derzeit um eine Betasoftware, die noch in Arbeit ist.

Alle Kernfunktionen sind implementiert und funktionieren, aber Ergänzungen werden wahrscheinlich auftreten, wenn die reale Nutzung erforscht wird.

Es kann zu Fehlern kommen oder die Kompatibilität nach einem Update ist nicht mehr gewährleistet.

Die vollständige Dokumentation ist noch nicht verfügbar. Aus Zeitmangel kann ich auch nicht sagen, wann diese weiterbearbeitet werden wird.


## Bilder / Verwendungsbeispiele

## Installations Handbuch

### Installieren:
- Installieren Sie alle erforderlichen Voraussetzungen. (Standardinstallation von Reticulum. Nur erforderlich, wenn Reticulum noch nicht installiert ist).
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
- Ändern Sie die Reticulum-Konfiguration entsprechend Ihren Anforderungen und Ihrem Anwendungsfall.
  ```bash
  nano /.reticulum/config
  ```
- Laden Sie die [Datei](lxmf_provisioning.py) aus diesem Repository herunter.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_provisioning/lxmf_provisioning.py
  ```
- Machen Sie es mit folgendem Befehl ausführbar
  ```bash
  chmod +x lxmf_provisioning.py
  ```

### Starten:
- Starte mit
  ```bash
  ./lxmf_provisioning.py
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.
- Beispiel einer Minimalkonfiguration (Überschreibung der Standardkonfiguration `config.cfg`). Dies sind die wichtigsten Einstellungen, die angepasst werden müssen. Alle anderen Einstellungen befinden sich in `config.cfg`.
  ```bash
  nano /root/.lxmf_provisioning/config.cfg.owr
  ```
  ```bash
  ```
- Starten Sie erneut. Fertig!
  ```bash
  ./lxmf_provisioning.py
  ```


### Als Systemdienst/Dämon ausführen:
- Erstellen Sie eine Servicedatei.
  ```bash
  nano /etc/systemd/system/lxmf_provisioning.service
  ```
- Kopieren Sie den folgenden Inhalt und passen Sie ihn an Ihre eigenen Bedürfnisse an.
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
  ExecStart=/root/lxmf_provisioning.py
  [Install]
  WantedBy=multi-user.target
  ```
- Aktivieren Sie den Dienst.
  ```bash
  systemctl enable lxmf_provisioning
  ```
- Starten Sie den Dienst.
  ```bash
  systemctl start lxmf_provisioning
  ```


### Dienst starten/stoppen:
  ```bash
  systemctl start lxmf_provisioning
  systemctl stop lxmf_provisioning
  ```


### Dienst aktivieren/deaktivieren:
  ```bash
  systemctl enable lxmf_provisioning
  systemctl disable lxmf_provisioning
  ```


### Führen Sie mehrere Instanzen aus (Kopieren der gleichen Anwendung):
- Führen Sie das Programm mit einem anderen Konfigurationspfad aus.
  ```bash
  ./lxmf_provisioning.py -p /root/.lxmf_provisioning_2nd
  ./lxmf_provisioning.py -p /root/.lxmf_provisioning_3nd
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.


### Erste Verwendung:
- Bei einem manuellen Start über die Konsole wird die eigene LXMF-Adresse angezeigt:
  ```
  [] ...............................................................................
  [] LXMF - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- In der Standardeinstellung wird diese Adresse auch beim Start bekannt gegeben.
- Diese Provisioning-Server-Adresse muss den Clients hinzugefügt werden.
- Nun kann die Software verwendet werden.


### Startup Parameter:
```bash
usage: lxmf_provisioning.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride]

LXMF Provisioning Server -

optionale Argumente:
  -h, --help            diese Hilfemeldung anzeigen und beenden
  -p PATH, --path PATH  Pfad zum alternativen Konfigurationsverzeichnis
  -pr PATH_RNS, --path_rns PATH_RNS
                        Pfad zum alternativen Reticulum-Konfigurationsverzeichnis
  -pl PATH_LOG, --path_log PATH_LOG
                        Pfad zum alternativen Protokollverzeichnis
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Läuft als Dienst und Loggt in Datei
  --exampleconfig       Ausführliches Konfigurationsbeispiel nach stdout ausgeben und beenden
  --exampleconfigoverride
                        Ausführliches Konfigurationsbeispiel nach stdout ausgeben und beenden
```


### Configurationsdaten Dateien:
- config.cfg
  
  Dies ist die Standardkonfigurationsdatei.

- config.cfg.owr
  
  Dies ist die Benutzerkonfigurationsdatei, die die Standardkonfigurationsdatei außer Kraft setzt.
  Alle hier vorgenommenen Einstellungen haben Vorrang.
  In dieser Datei können alle vom Standard abweichenden Einstellungen übersichtlich zusammengefasst werden.
  Dies hat auch den Vorteil, dass alle geänderten Einstellungen bei einer Aktualisierung des Programms beibehalten werden können.


## Konfigurations Handbuch (Beispiele)
Die hier gezeigten Konfigurationen sind nur ein Teil der Gesamtkonfiguration.
Sie dient nur dazu, die für die jeweilige Funktion notwendige und angepasste Konfiguration zu zeigen.
Alle Konfigurationen müssen in der Datei `config.cfg.owr` vorgenommen werden.
Alle möglichen Einstellungen sind in der Standard-Konfigurationsdatei `config.cfg` zu sehen.


### Standardfunktion (Versionen ankündigen, Benutzerregistrierung, Telemetrie):
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


### Benutzerdefinierte Funktion (Versionen ankündigen):
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
  registration = False
  telemetry = False
  
  [data]
  v_s = 0.1.4 #Version software
  v_c = 2022-11-29 20:00 #Version config
  v_d = 2022-11-29 20:00 #Version data
  v_a = 2022-11-29 20:00 #Version auth
  u_s = https:// #URL Software
  ```


## Handbuch für Administratoren
Dieses Handbuch gilt für alle Admins. Hier werden die administrativen Möglichkeiten kurz erläutert.


## Benutzerhandbuch
Diese Anleitung gilt für Benutzer oder Administratoren. Hier werden kurz die normalen Möglichkeiten der Software erklärt.


## FAQ

### Wie kann ich mit der Software beginnen?
Sie sollten den Abschnitt `Installationsanleitung` lesen. Dort ist alles kurz erklärt. Gehen Sie einfach alles von oben nach unten durch :)
