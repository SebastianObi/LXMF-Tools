# lxmf_distribution_group
Dieses Programm bietet eine E-Mail-ähnliche Verteilergruppe für die "Communicator" app. Welches ein anderes Projekt ist, das nicht Teil dieses github ist. Es verteilt eingehende LXMF-Nachrichten an mehrere Empfänger.

Weitere Informationen finden Sie in den Konfigurationsoptionen (am Ende der Programmdateien). Alles Weitere ist dort kurz dokumentiert. Nach dem ersten Start wird diese Konfiguration als Standardkonfiguration in der entsprechenden Datei angelegt.


### Merkmale
- Kompatibel mit (Communicator welches ein anderes Projekt ist, das nicht Teil dieses github ist)
- Server-/Node-basierte Nachrichtenweiterleitung und -verarbeitung
- Direkte oder propagierte Nachrichtenzustellung (Empfangen/Senden)
- Einfache Gruppenfunktionen (wie in anderen Messenger-Apps)
- Benutzerautorisierung und Berechtigungen
- Verschiedene Benutzertypen mit unterschiedlichen Berechtigungen
- Automatischer oder manueller Gruppenbeitritt
- Einfache Konfiguration in lesbaren Konfigurationsdateien
- Unterstützung mehrerer Sprachen (Englisch & Deutsch sind voreingestellt)


## Beispiele für die Verwendung

### Lokale autarke Gruppe
In einer kleinen Gruppe von Personen kann diese Gruppensoftware auf einem zentral gelegenen Knoten gehostet werden. Dies ermöglicht es den Nutzern, über diese Gruppe miteinander zu kommunizieren.

### Mehrere lokale autarke Gruppen
Auf demselben Knoten/Server können mehrere Gruppen unabhängig voneinander betrieben werden. Wie das funktioniert, wird weiter unten in der Installationsanleitung beschrieben.

### Allgemeine Informationen zum Transport der Nachrichten
Alle Nachrichten zwischen Client<->Gruppenserver werden als einzelne 1:1 Nachrichten im LXMF/Reticulum Netzwerk transportiert.
Dementsprechend findet zwischen diesen Endpunkten eine Verschlüsselung statt.
Wenn eine direkte Zustellung der Nachricht nicht funktioniert, wird sie an einen Propagierungsknoten gesendet. Dort wird sie zwischengespeichert und kann später vom Client abgerufen werden.

Es gibt keinen zentralen Server für die Kommunikation zwischen den einzelnen Gruppen. Dies bietet den Vorteil, dass alle Gruppen autonom arbeiten. Ein Ausfall einer Gruppe betrifft nur diese eine lokale Gruppe. 


## Aktueller Status
Es handelt sich derzeit um eine Betasoftware, die noch in Arbeit ist.

Alle Kernfunktionen sind implementiert und funktionieren, aber Ergänzungen werden wahrscheinlich auftreten, wenn die reale Nutzung erforscht wird.

Es kann zu Fehlern kommen oder die Kompatibilität nach einem Update ist nicht mehr gewährleistet.

Die vollständige Dokumentation ist noch nicht verfügbar. Aus Zeitmangel kann ich auch nicht sagen, wann diese weiterbearbeitet werden wird.


## Entwicklungsfahrplan
- Geplant, aber noch nicht terminiert
  - Vollständige Dokumentation


## Bilder/ Verwendungsbeispiele
<img src="../docs/screenshots/lxmf_distribution_group_01.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_02.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_03.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_04.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_05.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_06.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_07.png" width="200px"><img src="../docs/screenshots/lxmf_distribution_group_08.png" width="200px">


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
- Laden Sie die [Datei](lxmf_distribution_group.py) aus diesem Repository herunter.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/LXMF-Tools/main/lxmf_distribution_group/lxmf_distribution_group.py
  ```
- Machen Sie es mit folgendem Befehl ausführbar
  ```bash
  chmod +x lxmf_distribution_group.py
  ```

### Starten:
- Start mit
  ```bash
  ./lxmf_distribution_group.py
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.
- Beispiel einer Minimalkonfiguration (Überschreibung der Standardkonfiguration `config.cfg`). Dies sind die wichtigsten Einstellungen, die angepasst werden müssen. Alle anderen Einstellungen befinden sich in `config.cfg`.
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
- Starten Sie erneut. Fetig!
  ```bash
  ./lxmf_distribution_group.py
  ```


### Als Systemdienst/Dämon ausführen:
- Erstellen Sie eine Servicedatei.
  ```bash
  nano /etc/systemd/system/lxmf_distribution_group.service
  ```
- Kopieren Sie den folgenden Inhalt und passen Sie ihn an Ihre eigenen Bedürfnisse an.
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
  ExecStart=/root/lxmf_distribution_group.py
  [Install]
  WantedBy=multi-user.target
  ```
- Aktivieren Sie den Dienst.
  ```bash
  systemctl enable lxmf_distribution_group
  ```
- Starten Sie den Dienst.
  ```bash
  systemctl start lxmf_distribution_group
  ```


### Dienst starten/stoppen:
  ```bash
  systemctl start lxmf_distribution_group
  systemctl stop lxmf_distribution_group
  ```


### Aktivieren/Deaktivieren des Dienstes:
  ```bash
  systemctl enable lxmf_distribution_group
  systemctl disable lxmf_distribution_group
  ```


### Mehrere Instanzen ausführen (um dieselbe Anwendung zu kopieren):
- Führen Sie das Programm mit einem anderen Konfigurationspfad aus.
  ```bash
  ./lxmf_distribution_group.py -p /root/.lxmf_distribution_group_2nd
  ./lxmf_distribution_group.py -p /root/.lxmf_distribution_group_3nd
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.


### Erste Verwendung:
- Bei einem manuellen Start über die Konsole wird die eigene Gruppen-LXMF-Adresse angezeigt:
  ```
  [] ...............................................................................
  [] LXMF - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- In der Standardeinstellung wird diese Adresse auch beim Start bekannt gegeben.
- Wenn auto add user aktiv ist (Standardeinstellung), können Sie einfach eine erste Nachricht über Sideband/NomadNet an diese Adresse senden. Danach sind Sie Mitglied der Gruppe und können die Funktionen nutzen.
- Alternativ können die Benutzer auch manuell in der Datei `data.cfg` eingetragen werden. Es ist notwendig, hier einen Admin-Benutzer hinzuzufügen, um alle Befehle über LXMF-Nachrichten nutzen zu können!
- Nun kann die Gruppe benutzt werden.


### Parameter für die Inbetriebnahme:
```bash
usage: lxmf_distribution_group.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride] [--exampledata]

LXMF Distribution Group - Server-seitige Gruppenfunktionen für LXMF-basierte Anwendungen

optionale Argumente:
  -h, --help            diese Hilfemeldung anzeigen und beenden
  -p PATH, --path PATH  Pfad zum alternativen Konfigurationsverzeichnis
  -pr PATH_RNS, --path_rns PATH_RNS
                        Pfad zum alternativen Reticulum-Konfigurationsverzeichnis
  -pl PATH_LOG, --path_log PATH_LOG
                        Pfad zum alternativen Protokollverzeichnis
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Läuft als Dienst und sollte sich in der Datei
  --exampleconfig       Ausführliches Konfigurationsbeispiel nach stdout ausgeben und beenden
  --exampleconfigoverride
                        Ausführliches Konfigurationsbeispiel nach stdout ausgeben und beenden
  --exampledata         Ausführliches Konfigurationsbeispiel nach stdout ausgeben und beenden
```


### Configurationsdaten Dateien:
- config.cfg
  
  Dies ist die Standardkonfigurationsdatei.

- config.cfg.owr
  
  Dies ist die Benutzerkonfigurationsdatei, die die Standardkonfigurationsdatei außer Kraft setzt.
  Alle hier vorgenommenen Einstellungen haben Vorrang.
  In dieser Datei können alle vom Standard abweichenden Einstellungen übersichtlich zusammengefasst werden.
  Dies hat auch den Vorteil, dass alle geänderten Einstellungen bei einer Aktualisierung des Programms beibehalten werden können.

- data.cfg
  
  Dies ist die Datendatei. Sie wird automatisch erstellt und gespeichert/überschrieben.
  Sie enthält Daten, die von der Software selbst verwaltet werden.
  Wenn hier manuelle Anpassungen vorgenommen werden, muss das Programm vorher beendet werden!


## Konfigurationshandbuch (Beispiele)
Die hier gezeigten Konfigurationen sind nur ein Teil der Gesamtkonfiguration.
Sie dienen nur dazu, die für die jeweilige Funktion notwendige und angepasste Konfiguration zu zeigen.
Alle Konfigurationen müssen in der Datei `config.cfg.owr` vorgenommen werden.
Alle möglichen Einstellungen sind in der Standard-Konfigurationsdatei `config.cfg` zu sehen.


### Ankündigung der Gruppe:
- `config.cfg.owr`
  ```
  [lxmf]
  announce_startup = Yes
  announce_startup_delay = 0 #Seconds
  announce_periodic = Yes
  announce_periodic_interval = 120 #Minutes
  ```


### Message propagation - Senden:
- `config.cfg.owr`
  ```
  [lxmf]
  desired_method = direct #direct/propagated
  propagation_node = ca2762fe5283873719aececfb9e18835
  try_propagation_on_fail = Yes
  ```


### Message propagation - Empfang(Sync vom Knoten):
- `config.cfg.owr`
  ```
  [lxmf]
  propagation_node = ca2762fe5283873719aececfb9e18835
  sync_startup = Yes
  sync_startup_delay = 30 #Seconds
  sync_periodic = Yes
  sync_periodic_interval = 30 #Minutes
  sync_limit = 8
  ```


## Administratoren Handbuch
Dieses Handbuch gilt für alle Admins. Hier werden die administrativen Möglichkeiten kurz erläutert.

Ein Administartor hat entsprechend höhere Rechte und es stehen mehr Befehle zur Verfügung. Generell können die Berechtigungen frei definiert werden. Alle Benutzer/Admins etc. können auch generell die gleichen Berechtigungen haben.


## User Handbuch
Diese Anleitung gilt für Benutzer oder Administratoren. Hier werden kurz die normalen Möglichkeiten der Software erklärt.


### Starten Sie die Gruppe und treten Sie ihr bei:
Senden Sie einfach eine erste Nachricht an die Gruppenadresse mit Sideband/NomadNet.
Dies ist jedoch nur möglich, wenn der automatische Beitritt zur Gruppe aktiviert ist.


## FAQ

### Warum diese serverbasierte Gruppenfunktion und keine direkten Gruppen in der Client-Software?
Zum Zeitpunkt der Entwicklung dieser Gruppenfunktionen gab es keine andere Möglichkeit, Gruppen über Sideband/Nomadnet zu verwenden. Daher wurde diese Software als Workaround entwickelt.
Diese Software bietet auch andere Funktionen als eine normale Gruppenübertragung.

### Wie kann ich mit der Software beginnen?
Sie sollten den Abschnitt `Installationsanleitung` lesen. Dort ist alles kurz erklärt. Gehen Sie einfach alles von oben nach unten durch :)