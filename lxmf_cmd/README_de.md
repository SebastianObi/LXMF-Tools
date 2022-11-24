# lxmf_cmd
Dieses Programm führt jeden per Nachricht empfangenen Text als Systembefehl aus und gibt die Ausgabe des Befehls als Nachricht zurück. Es können nur einzelne Befehle direkt ausgeführt werden. Es wird kein interaktives Terminal erzeugt.

Weitere Informationen finden Sie in den Konfigurationsoptionen (am Ende der Programmdateien). Alles Weitere ist dort kurz dokumentiert. Nach dem ersten Start wird diese Konfiguration als Standardkonfiguration in der entsprechenden Datei angelegt.


### Merkmale
- Kompatibel mit allen LXMF-Anwendungen (NomadNet, Sideband, ...)


## Beispiele für die Verwendung

### 

### Allgemeine Informationen zum Transport der Nachrichten
Alle Nachrichten zwischen Client<->Server werden als einzelne 1:1 Nachrichten im LXMF/Reticulum Netzwerk transportiert.
Dementsprechend findet zwischen diesen Endpunkten eine Verschlüsselung statt.
Wenn eine direkte Zustellung der Nachricht nicht funktioniert, wird sie an einen Propagationsknoten gesendet. Dort wird sie zwischengespeichert und kann später vom Client abgerufen werden.

Da es sich um normale LXMF-Nachrichten handelt, kann jede LXMF-fähige Anwendung zur Kommunikation mit der Gruppe verwendet werden.


## Aktueller Status
Die Software befindet sich noch in der Beta-Phase und ist noch nicht fertiggestellt.

Alle Kernfunktionen sind implementiert und funktionieren, aber Ergänzungen werden wahrscheinlich auftreten, wenn die praktische Anwendung erforscht wird.

Es kann zu Fehlern kommen oder die Kompatibilität nach einem Update ist nicht mehr gewährleistet.

Die vollständige Dokumentation ist noch nicht verfügbar. Aus Zeitmangel kann ich auch nicht sagen, wann diese weiterbearbeitet werden wird.


## Bilder/ Beispiele für den Gebrauch
<img src="../docs/screenshots/lxmf_cmd_01.png" width="200px">

## Installations Handbuch

### Installation:
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
- Laden Sie die [Datei](lxmf_cmd.py) aus diesem Repository herunter.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_cmd/lxmf_cmd.py
  ```
- Machen Sie es mit folgendem Befehl ausführbar
  ```bash
  chmod +x lxmf_cmd.py
  ```

### Starten:
- Start mit
  ```bash
  ./lxmf_cmd.py
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.
- Beispiel einer Minimalkonfiguration (Überschreibung der Standardkonfiguration `config.cfg`). Dies sind die wichtigsten Einstellungen, die angepasst werden müssen. Alle anderen Einstellungen befinden sich in `config.cfg`.
  ```bash
  nano /root/.lxmf_cmd/config.cfg.owr
  ```
  ```bash
  ```
- Starten Sie erneut. Fertig!
  ```bash
  ./lxmf_cmd.py
  ```


### Als Systemdienst/Dämon ausführen:
- Erstellen Sie eine Servicedatei.
  ```bash
  nano /etc/systemd/system/lxmf_cmd.service
  ```
- Kopieren Sie den folgenden Inhalt und passen Sie ihn an Ihre eigenen Bedürfnisse an.
  ```bash
  [Unit]
  Description=lxmf_cmd.py Daemon
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  ExecStart=/root/lxmf_cmd.py
  [Install]
  WantedBy=multi-user.target
  ```
- Aktivieren Sie den Dienst.
  ```bash
  systemctl enable lxmf_cmd
  ```
- Starten Sie den Dienst.
  ```bash
  systemctl start lxmf_cmd
  ```


### Dienst starten/stoppen:
  ```bash
  systemctl start lxmf_cmd
  systemctl stop lxmf_cmd
  ```


### Dienst aktivieren/deaktivieren:
  ```bash
  systemctl enable lxmf_cmd
  systemctl disable lxmf_cmd
  ```


### Führen Sie mehrere Instanzen aus (Kopieren der gleichen Anwendung):
- Führen Sie das Programm mit einem anderen Konfigurationspfad aus.
  ```bash
  ./lxmf_cmd.py -p /root/.lxmf_cmd_2nd
  ./lxmf_cmd.py -p /root/.lxmf_cmd_3nd
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
- Nun kann die Software verwendet werden.


### Parameter für die Inbetriebnahme:
```bash
usage: lxmf_cmd.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride]

LXMF CMD -

optionale Argumente:
  -h, --help            diese Hilfemeldung anzeigen und beenden
  -p PATH, --path PATH  Pfad zum alternativen Konfigurationsverzeichnis
  -pr PATH_RNS, --path_rns PATH_RNS
                        Pfad zum alternativen Reticulum-Konfigurationsverzeichnis
  -pl PATH_LOG, --path_log PATH_LOG
                        Pfad zum alternativen Protokollverzeichnis
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Läuft als Dienst und sollte Loggen in die Datei
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


## Konfigurationshandbuch (Beispiele)
Die hier gezeigten Konfigurationen sind nur ein Teil der Gesamtkonfiguration.
Sie dienen nur dazu, die für die jeweilige Funktion notwendige und angepasste Konfiguration zu zeigen.
Alle Konfigurationen müssen in der Datei `config.cfg.owr` vorgenommen werden.
Alle möglichen Einstellungen sind in der Standard-Konfigurationsdatei `config.cfg` zu sehen.


## Administratoren Handbuch
Dieses Handbuch gilt für alle Admins. Hier werden die administrativen Möglichkeiten kurz erläutert.


## User Handbuch
Diese Anleitung gilt für Benutzer oder Administratoren. Hier werden kurz die normalen Möglichkeiten der Software erklärt.


## FAQ

### Wie kann ich mit der Software beginnen?
Sie sollten den Abschnitt `Installationsanleitung` lesen. Dort ist alles kurz erklärt. Gehen Sie einfach alles von oben nach unten durch :)