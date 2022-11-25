# lxmf_distribution_group
Dieses Programm bietet eine E-Mail-ähnliche Verteilergruppe. Es verteilt eingehende LXMF-Nachrichten an mehrere Empfänger. Da dieses Programm wie ein normaler LXMF-Endpunkt agiert, können alle kompatiblen Chat-Anwendungen verwendet werden. Zusätzlich zum einfachen Messaging gibt es eine einfache kommandobasierte Benutzeroberfläche. Hier können alle relevanten Aktionen für die tägliche Verwaltung durchgeführt werden. Die Grundkonfiguration wird in den Konfigurationsdateien vorgenommen. Es gibt verschiedene Optionen, um das gesamte Verhalten der Gruppe an die eigenen Bedürfnisse anzupassen. Diese Verteilergruppe ist viel mehr als eine Standard-E-Mail-Verteilergruppe. Sie emuliert erweiterte Gruppenfunktionen mit automatischen Benachrichtigungen usw. Es können verschiedene Benutzerberechtigungen definiert werden. Für jeden Benutzertyp kann der Funktionsumfang individuell festgelegt werden. Die normalen Benutzer haben nur geringe Rechte. Während ein Moderator oder Admin mit einfachen Befehlen alles Notwendige erledigen kann. Ist die Grundkonfiguration einmal erledigt, kann alles Weitere über LXMF-Nachrichten als Befehle erfolgen.

Weitere Informationen finden Sie in den Konfigurationsoptionen (am Ende der Programmdateien). Alles Weitere ist dort kurz dokumentiert. Nach dem ersten Start wird diese Konfiguration als Standardkonfiguration in der entsprechenden Datei angelegt.


### Merkmale
- Kompatibel mit allen LXMF-Anwendungen (NomadNet, Sideband, ...)
- Server-/Node-basierte Nachrichtenweiterleitung und -verarbeitung
- Direkte oder propagierte Nachrichtenzustellung (Empfangen/Senden)
- Einfache Gruppenfunktionen (wie in anderen Messenger-Apps)
- Benutzerautorisierung und Berechtigungen
- Verschiedene Benutzertypen mit unterschiedlichen Berechtigungen
- Automatischer oder manueller Gruppenbeitritt
- Textbasierte Schnittstelle zur Anzeige von erweiterten Funktionen oder Informationen
- Cluster von mehreren Gruppen (Kommunikation zwischen Gruppen mit verschiedenen Levels)
- Automatisches Aushandeln von Clustern
- Statistiken auf Cluster-, Router-, Gruppen- und Benutzerebene
- Einfache Konfiguration in lesbaren Konfigurationsdateien
- Verschiedene Admin-Befehle für die täglichen Aufgaben, die über LXMF-Nachrichten gesteuert werden
- Gruppenbeschreibung, Regeln und gepinnte Nachrichten
- Optional aktivierbarer Warteraum für neue Mitglieder vor dem Beitritt zur Gruppe
- Unterstützung mehrerer Sprachen (Englisch & Deutsch sind voreingestellt)


## Beispiele für die Verwendung

### Lokale autarke Gruppe
In einer kleinen Gruppe von Personen kann diese Gruppensoftware auf einem zentral gelegenen Knoten gehostet werden. Dies ermöglicht es den Nutzern, über diese Gruppe miteinander zu kommunizieren.

### Mehrere lokale autarke Gruppen
Auf demselben Knoten/Server können mehrere Gruppen unabhängig voneinander betrieben werden. Wie das funktioniert, wird weiter unten in der Installationsanleitung beschrieben.

### Vernetzung von Gruppen zu einem Cluster
Es ist möglich, mehrere lokal unabhängige Gruppen zu einem Cluster zu verbinden. Dadurch ist es möglich, Nachrichten von einer Gruppe zur anderen zu senden.

### Hierarchische Clustergruppen über weit verteilte Gebiete
Ein Gruppencluster kann in mehreren Ebenen gebildet werden. Entsprechend der Benennung der Ebenen kann eine Gruppe mit mehreren Namen versehen werden.
Dadurch ist es möglich, z.B. eine Nachricht an mehrere Gruppen gleichzeitig zu senden. So könnten Sie die Gruppennamen wie folgt definieren. Land/Region/Stadt".
Damit ist es möglich, alle Gruppen eines bestimmten Landes oder einer bestimmten Region zu kontaktieren.

### Allgemeine Informationen zum Transport der Nachrichten
Alle Nachrichten zwischen Client<->Gruppenserver und Gruppenserver<->Gruppenserver werden als einzelne 1:1 Nachrichten im LXMF/Reticulum Netzwerk transportiert.
Dementsprechend findet zwischen diesen Endpunkten eine Verschlüsselung statt.
Wenn eine direkte Zustellung der Nachricht nicht funktioniert, wird sie an einen Propagierungsknoten gesendet. Dort wird sie zwischengespeichert und kann später vom Client abgerufen werden.

Da es sich um normale LXMF-Nachrichten handelt, kann jede LXMF-fähige Anwendung zur Kommunikation mit der Gruppe verwendet werden.

Wenn eine Nachricht an einen mehrstufigen (hierarchischen) Cluster gesendet wird. Es wird immer eine 1:1-Verbindung von der Quelle zu jeder Zielgruppe in dieser Clusterebene hergestellt.

Es gibt keinen zentralen Server für die Kommunikation zwischen den einzelnen Gruppen. Dies bietet den Vorteil, dass alle Gruppen autonom arbeiten. Ein Ausfall einer Gruppe betrifft nur diese eine lokale Gruppe. 


## Aktueller Status
Es handelt sich derzeit um eine Betasoftware, die noch in Arbeit ist.

Alle Kernfunktionen sind implementiert und funktionieren, aber Ergänzungen werden wahrscheinlich auftreten, wenn die reale Nutzung erforscht wird.

Es kann zu Fehlern kommen oder die Kompatibilität nach einem Update ist nicht mehr gewährleistet.

Die vollständige Dokumentation ist noch nicht verfügbar. Aus Zeitmangel kann ich auch nicht sagen, wann diese weiterbearbeitet werden wird.


## Entwicklungsfahrplan
- Geplant, aber noch nicht terminiert
  - Propagationsknoten-Fallback
  - Automatisches Erkennen von Propagationsknoten
  - Propagation Node auto select
  - Parameter für die Sicherung/Wiederherstellung von Konfiguration und Daten
  - Parameter für die Sicherung/Wiederherstellung der Identität
  - Cluster-Brücken/Wiederholer
  - Unterschiedliche Nachrichtenprioritäten
  - Fallback-Lösung: Master/Slave
  - Zentralisierte Benutzer-/Gruppenautorisierung
  - Interne Warteschlange mit Priorisierung
  - Intelligenteres Senden von Nachrichten
  - Befehl zur Anzeige des Sendestatus der letzten Nachricht
  - Automatische Sendebestätigung
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
  # Dies ist die Benutzerkonfigurationsdatei, die die Standardkonfigurationsdatei außer Kraft setzt.
  # Alle hier vorgenommenen Einstellungen haben Vorrang.
  # Diese Datei kann verwendet werden, um alle Einstellungen, die vom Standard abweichen, übersichtlich zusammenzufassen.
  # Dies hat auch den Vorteil, dass alle geänderten Einstellungen bei einem Update des Programms erhalten bleiben können.
  
  
  #### Hauptprogrammeinstellungen ####
  [main]
  
  # Standardsprache wählen.
  lng = en # en/de
  
  
  #### LXMF-Verbindungseinstellungen ####
  [lxmf]
  
  # Der Name ist für andere Peers sichtbar
  # im Netzwerk sichtbar und in Ankündigungen enthalten.
  # Er wird auch in der Gruppenbeschreibung/Info verwendet.
  display_name = Distribution Group
  
  # Propagationsknoten Adresse/Hash.
  propagation_node = ca2762fe5283873719aececfb9e18835
  
  # Versuchen Sie, eine Nachricht über das LXMF-Verbreitungsnetz zuzustellen,
  # wenn eine direkte Zustellung an den Empfänger nicht möglich ist.
  try_propagation_on_fail = Yes
  
  
  #### Cluster Einstellungen ####
  [cluster]
  
  # Aktivieren/Deaktivieren Sie diese Funktion.
  enabled = True
  
  # Um mehrere komplett getrennte Cluster/Gruppen zu verwenden,
  # kann hier ein individueller Name und Typ vergeben werden.
  name = grp
  type = cluster
  
  # Schrägstrich-getrennte Liste mit den Namen dieses Clusters.
  # Diese Funktion kann verwendet werden, um mehrstufige Gruppenstrukturen aufzubauen.
  # Alle Sendenachrichten, die mit dem Namen übereinstimmen (alle Ebenen), werden empfangen.
  # Der letzte Name ist der Hauptname dieser Gruppe und wird als Quelle für Sendenachrichten verwendet.
  # Leerzeichen sind im Namen nicht erlaubt.
  display_name = County/Region/City
  
  
  #### Router Einstellungen ####
  [router]
  
  # Aktivieren/Deaktivieren der Routerfunktionalität.
  enabled = True
  
  # Komma-getrennte Liste mit den Namen, für die die Nachrichten weitergeleitet/wiederholt werden sollen.
  # Die Namen und Ebenen müssen mit dem verwendeten display_name des Clusters übereinstimmen.
  # Es sind keine Leerzeichen im Namen erlaubt.
  display_name = Country,County/Region
  
  
  #### Hochverfügbarkeitseinstellungen ####
  [high_availability]
  
  # Aktivieren/Deaktivieren Sie diese Funktion.
  enabled = False
  
  # Rolle dieses Knotens (Master/Slave)
  role = master
  
  # Peer Addresse
  peer = 
  
  
  #### Statistik/Zähler-Einstellungen ####
  [statistic]
  
  # Aktivieren/Deaktivieren Sie diese Funktion.
  enabled = True
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
  Description=lxmf_distribution_group.py Daemon
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


### Cluster:
Dieses Beispiel zeigt die Konfiguration für einen Cluster mit 2 Gruppen. Dies ermöglicht die Kommunikation zwischen beiden Gruppen.
Es ist möglich, direkt in jede Gruppe zu schreiben oder in die übergeordnete Ebene, die dann beide Gruppen umfasst.

- Group #1 `config.cfg.owr`
  ```
  [lxmf]
  display_name = Group Test 1
  [cluster]
  enabled = True
  name = test
  type = cluster
  display_name = Germany/NRW/Düsseldorf
  ```

- Group #1 `data.cfg`
  ```
  [main]
  enabled_cluster = True
  auto_add_cluster = True
  ```

- Group #2 `config.cfg.owr`
  ```
  [lxmf]
  display_name = Group Test 2
  [cluster]
  enabled = True
  name = test
  type = cluster
  display_name = Germany/Bayern/München
  ```

- Group #2 `data.cfg`
  ```
  [main]
  enabled_cluster = True
  auto_add_cluster = True
  ```


### 2 unabhängige Cluster:
Dieses Beispiel zeigt die Konfiguration für 2 separate Cluster.
Damit ist es möglich, mehrere Cluster parallel über das gleiche Kommunikationsnetz zu betreiben.
Es ist wichtig, `Name` und `Typ` unterschiedlich zu konfigurieren.

- Cluster #1 - Group #1 `config.cfg.owr`
  ```
  [lxmf]
  display_name = Group Test 1
  [cluster]
  enabled = True
  name = test1
  type = cluster
  display_name = Germany/NRW/Düsseldorf
  ```

- Cluster #1 - Group #1 `data.cfg`
  ```
  [main]
  enabled_cluster = True
  auto_add_cluster = True
  ```

- Cluster #2 - Group #1 `config.cfg.owr`
  ```
  [lxmf]
  display_name = Group Test 1
  [cluster]
  enabled = True
  name = test2
  type = cluster
  display_name = Germany/NRW/Düsseldorf
  ```

- Cluster #2 - Group #1 `data.cfg`
  ```
  [main]
  enabled_cluster = True
  auto_add_cluster = True
  ```


### Mitglieder/Cluster:
Normalerweise werden alle Daten hier (`data.cfg`) automatisch von der Software erstellt. Basierend auf der automatischen Erstellung von neuen Benutzern/Clustern oder ausgeführten Befehlen zur Verwaltung.
Hier sind ein paar Beispiele, wie der Inhalt aussehen kann. Natürlich kann die Datei auch manuell bearbeitet werden. Dies ist notwendig, wenn ein automatisches Hinzufügen deaktiviert ist.
Bitte vergessen Sie nicht, das Programm vorher zu schließen!

- Group #1 `data.cfg`
  ```
  [user]
  04652a820cc69d47940ce39050c455a6 = Test User 1
  
  [cluster]
  d1b551e1b89fff5a4a6f2aaff2464971 = Germany/Bayern/München
    ```

- Group #2 `data.cfg`
  ```
    [user]
  18201a931dd69d47940ce39050c487c9 = Test User 1
  
  [cluster]
  801f48d54bc71cb3e0886944832aaf8d = Germany/NRW/Düsseldorf
    ```


### Cluster router:
Noch nicht umgesetzt


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


### Warteraum für neue Mitglieder:
Dieses Beispiel zeigt die Konfiguration für einen Warteraum für neue Mitglieder.
Wenn ein unbekannter Benutzer der Gruppe durch die erste Nachricht an die Gruppe beitritt, wird er zum Typ "Warten" hinzugefügt.
Dort befindet er sich dann in einer Art Warteraum, in dem keine Nachrichten geschrieben und empfangen werden können.
Ein Admin oder Moderator kann dann diesen Benutzer zulassen oder verbieten.

Die Konfiguration zeigt nur den minimal notwendigen Teil für diese Funktionalität. Natürlich können den Benutzern weitere Rechte zugewiesen werden.

- `config.cfg.owr`
  ```
  [rights]
  admin = interface,receive_join,allow,deny
  mod = interface,receive_join,allow,deny
  wait = 
  
  [interface_messages]
  auto_add_wait = Welcome to the group "!display_name!"!!n!!n!You still need to be allowed to join. You will be notified automatically.
  auto_add_wait-de = Willkommen in der Gruppe "!display_name!"!!n!!n!Der Beitritt muss ihnen noch erlaubt werden. Sie werden darüber automatisch benachrichtigt.
  
  allow_user = You have been allowed to join the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Please assign a nickname with the command /name
  allow_user-de = Sie wurden erlaubt der Gruppe "!display_name!" beizutreten!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Bitte vergeben Sie einen Nickname mit dem Befehl /name
  
  deny_user = You have been denied to join the group "!display_name!"!
  deny_user-de = Ihnen wurde der Beitritt in die Gruppe "!display_name!" abgelehnt!
  
  member_join = !source_name! <!source_address!> joins the waiting room and must be allowed to join the group.
  member_join-de = !source_name! <!source_address!> betritt den Warteraum und muss zur Gruppe zugelassen werden.
  ```

- `data.cfg`
  ```
  [main]
  auto_add_user = True
  auto_add_user_type = wait
  allow_user = True
  allow_user_type = user
  deny_user = True
  deny_user_type = block_wait
  ```


## Administratoren Handbuch
Dieses Handbuch gilt für alle Admins. Hier werden die administrativen Möglichkeiten kurz erläutert.

Ein Administartor hat entsprechend höhere Rechte und es stehen mehr Befehle zur Verfügung. Generell können die Berechtigungen frei definiert werden. Alle Benutzer/Admins etc. können auch generell die gleichen Berechtigungen haben.


### Aktivieren/Deaktivieren von Funktionen:
Die folgenden Funktionen können per Befehl entsprechend eingestellt werden.

`/enable_local <true/false>` = Lokales Nachrichten Routing

`/enable_cluster <true/false>` = Cluster Nachrichten Routing

`/auto_add_user <true/false>` = Funktionalität für unbekannte Benutzer hinzufügen

`/auto_add_cluster <true/false>` = Funktionalität für unbekannte Cluster hinzufügen

### Werte ändern:
`/description <description>` = Beschreibung ändern

`/rules <description>` = Regeln ändern


### Senden Sie eine manuelle Ankündigung der Gruppe und des Clusters:
`/announce`


### Benutzer verwalten (Anzeige der vorhandenen Benutzer):
`/show or /list`

`/show or /list <admin/mod/user/guest>`

`/search <nickname/user_address>`


### Verwalten von Benutzern (einladen):
Zusätzliche Benutzer können eingeladen werden, dies geschieht mit dem Befehl `/invite <Benutzer_Adresse>`.
Dann erhält der Benutzer eine Willkommensnachricht und tritt der Gruppe bei.


### Benutzer verwalten (zulassen/verweigern):
Wenn das Wartezimmer aktiviert ist, können die Benutzer mit den folgenden 2 Befehlen verwaltet werden.

`/allow <user_address>`

`/deny <user_address>`


### Verwalten von Benutzern (hinzufügen/löschen/verschieben):
Die folgenden Befehle können zur Verwaltung der Benutzer verwendet werden.
Nur im Falle einer Einladung wird eine Willkommensnachricht an den Benutzer gesendet. Benutzer, die hier hinzugefügt werden, erhalten keine Benachrichtigung und müssen die erste Konversation mit der Gruppe selbst beginnen. Oder sie bekommen direkt eine Nachricht zugesandt.

`/add <admin/mod/user/guest> <user_address> <user_name>`

`/del or /rm <admin/mod/user/guest> <user_address>`

`/del or /rm <user_address>`

`/move <admin/mod/user/guest> <user_address>`


### Benutzer verwalten (kick/block/unblock):
Mit den folgenden Befehlen können Sie Benutzer entfernen/aktivieren.

`/kick <user_address>`

`/block <user_address>`

`/unblock <user_address>`


### Daten speichern:
Wenn in der Konfiguration ein automatisches Speichern eingestellt ist, muss hier nichts gemacht werden. Falls nicht oder zusätzlich können die Daten mit dem folgenden Befehl gespeichert werden.

`/save`


### Hilfe:
Um die Hilfe und alle verfügbaren Befehle anzuzeigen, können die folgenden Befehle verwendet werden. `/help` oder `/?`


### Beispiele für mögliche Befehle:
```
/help or /? = Zeigt diese Hilfe an
/leave or /part = Gruppe verlassen
/name = Aktuellen Nickname anzeigen
/nick = Aktuellen Nickname anzeigen
/name <your nickname> = Spitznamen ändern/festlegen
/nick <your nickname> = Spitznamen ändern/festlegen
/address = Adressdaten anzeigen
/info = Gruppeninfo anzeigen
/description = Aktuelle Beschreibung anzeigen
/rules = Aktuelle Regeln anzeigen
/version = Versionsinformationen anzeigen
/groups or /cluster = Alle Gruppen/Cluster anzeigen
/groups <name> = Suche nach einer Gruppe/einem Cluster anhand des Namens
/members or /names or /who = Alle Gruppenmitglieder zeigen
/admins = Gruppenadmins anzeigen
/moderators or /mods = Gruppenmoderatoren anzeigen
/users = Gruppenbenutzer anzeigen
/guests = Gruppengäste anzeigen
/search <nickname/user_address> = Sucht nach einem Benutzer anhand seines Spitznamens oder seiner Adresse
/whois <nickname/user_address> = Sucht nach einem Benutzer anhand seines Spitznamens oder seiner Adresse
/activitys = Benutzeraktivitäten anzeigen
/statistic or /stat = Gruppenstatistik anzeigen
/status = Status anzeigen
/delivery or /message = Zustellungsstatus der letzten Nachricht anzeigen
/enable_local <true/false> = Lokales Nachrichten Routing an/ausschalten
/enable_cluster <true/false> = Weiterleitung von Cluster Nachrichten an/ausschalten
/auto_add_user <true/false> = Funktionalität für unbekannte Benutzer an/ausschalten
/auto_add_user_type <admin/mod/user/guest>
/auto_add_cluster <true/false> = Unbekannte Cluster-Funktionalität hinzufügen
/invite_user <true/false> = Einladungsfunktion
/invite_user_type <admin/mod/user/guest>
/description <description> = Beschreibung ändern
/rules <description> = Regeln ändern
/announce = Ankündigung senden
/sync = Nachrichten mit dem Verbreitungsknoten synchronisieren
/show run = Aktuelle Konfiguration anzeigen
/show or /list
/show or /list <admin/mod/user/guest>
/add <admin/mod/user/guest> <user_address> <user_name>
/del or /rm <admin/mod/user/guest> <user_address>
/del or /rm <user_address>
/move <admin/mod/user/guest> <user_address>
/invite <user_address> = Lädt Benutzer zur Gruppe ein
/kick <user_address> = Schmeißt den Benutzer aus der Gruppe
/block <user_address> = Benutzer sperren
/ban <user_address> = Benutzer sperren
/unblock <user_address> = Benutzer entsperren
/unban <user_address> = Benutzer entsperren
/load or /read = Lesen der Konfiguration/Daten
/save or /wr = Speichert die aktuelle Konfiguration/Daten
```


## User Handbuch
Diese Anleitung gilt für Benutzer oder Administratoren. Hier werden kurz die normalen Möglichkeiten der Software erklärt.


### Starten Sie die Gruppe und treten Sie ihr bei:
Senden Sie einfach eine erste Nachricht an die Gruppenadresse mit Sideband/NomadNet.
Dies ist jedoch nur möglich, wenn der automatische Beitritt zur Gruppe aktiviert ist.


### Lokale Gruppennachricht senden:
Jeder normale Text ohne `/` oder `@` am Anfang wird als normale Nachricht interpretiert und entsprechend an alle lokalen Mitglieder gesendet. Es gibt hier nichts weiter zu beachten.


### Clusternachricht senden:
Es ist möglich, Nachrichten an andere Gruppen zu senden, die Teil des Clusters sind. Dazu müssen Sie zuerst den Befehl `@` gefolgt vom Zielnamen der Gruppe und dann den normalen Nachrichtentext eingeben.

Zum Beispiel `@Berlin Hallo dies ist ein Test :)`. Dieses Beispiel würde also diese Nachricht an die Gruppe Berlin senden.

Eine Gruppe in einem Cluster kann hierarchisch in verschiedenen Ebenen angeordnet sein. Wenn die übergeordnete Ebene als Ziel definiert ist, erhalten alle darunter liegenden Gruppen diese Nachricht.

Zum Beispiel gibt es die folgenden 3 Gruppen `Deutschland/Berlin` und `Deutschland/Hamburg` und `Deutschland/München`. Entsprechend können diese direkt oder eine höhere Ebene angeschrieben werden.

Mit dem Befehl `@Germany` sind nun alle 3 Gruppen erreichbar. Mit dem Befehl `@München` ist nur diese eine Gruppe zugänglich.


### Nachricht anheften (lokale Gruppe):
Es ist möglich, Nachrichten der lokalen Gruppe dauerhaft anzuheften. Diese wird dann an alle Mitglieder gesendet. Außerdem können alle angehefteten Nachrichten später angezeigt werden.

Diese Funktion ist nützlich, um neuen Mitgliedern Zugang zu wichtigen Nachrichten aus der Vergangenheit zu geben.

/pin" = Alle angehefteten Nachrichten anzeigen

/pin <Nachrichtentext>` = Eine neue Nachricht anheften

`/unpin <#id>` = Eine angeheftete Nachricht entfernen


### Nachricht anheften (Clustergruppe):
Es ist möglich, Nachrichten der Clustergruppe dauerhaft zu pinnen. Diese wird dann an alle Mitglieder gesendet. Außerdem können alle gepinnten Nachrichten später angezeigt werden.

Diese Funktion ist nützlich, um neuen Mitgliedern Zugang zu wichtigen Nachrichten aus der Vergangenheit zu geben.

`@Group /pin <Nachrichtentext>` = Eine neue Nachricht anheften


### Schnittstelle/Befehle:
Eine einfache textnachrichtenbasierte Benutzeroberfläche ist integriert. Wie Sie es vielleicht von anderen Chat-Programmen kennen. Jeder Befehl muss mit dem Begrenzungszeichen `/` beginnen. Dann folgen der Befehl und eventuelle Daten. Zum Beispiel `/name Mein neuer Nickname`.

Wenn kein `/` am Anfang steht, ist dies eine normale Nachricht und wird an die anderen Mitglieder gesendet.


### Hilfe:
Um die Hilfe und alle verfügbaren Befehle anzuzeigen, können die folgenden Befehle verwendet werden. `/help` oder `/?`


### Die Gruppe verlassen:
Der Befehl `/leave` wird verwendet, um die Gruppe zu verlassen. Danach kann die Gruppe wieder betreten werden (wenn dies erlaubt ist).


### Benutzer einladen:
Wenn der Administrator erlaubt hat, dass weitere Benutzer eingeladen werden, kann dies mit dem Befehl `/invite <Benutzer_Adresse>` geschehen.
Dann erhält der Benutzer eine Willkommensnachricht und tritt der Gruppe bei.


### Nickname ändern:
Der eigene Nickname wird entweder automatisch über die empfangene Ankündigung (nach dem Beitritt zur Gruppe) vergeben oder kann über den folgenden Befehl geändert werden.

`/name <Ihr neuer Nickname>` Zum Beispiel `/name Max Walker`.


### Beispiele für mögliche Befehle:
```
/help or /? = Zeigt diese Hilfe
/leave or /part = Gruppe verlassen
/name = Aktuellen Namen anzeigen
/nick = Aktuellen Namen anzeigen
/name <your nickname> = Name ändern/festlegen
/nick <your nickname> = Name ändern/festlegen
/address = Adressinformationen anzeigen
/info = Gruppeninformationen anzeigen
/description = Aktuelle Beschreibung anzeigen
/rules = Aktuelle Regeln anzeigen
/version = Versionsinformationen anzeigen
/groups or /cluster = Alle Gruppen/Cluster anzeigen
/groups <name> = Suche nach einer Gruppe/einem Cluster anhand des Namens
/members or /names or /who = Alle Gruppenmitglieder anzeigen
/admins = Gruppenadministratoren anzeigen
/moderators or /mods = Gruppenmoderatoren anzeigen
/users = Gruppenbenutzer anzeigen
/guests = Gruppengäste anzeigen
/search <nickname/user_address> = Sucht nach einem Benutzer anhand seines Namens oder seiner Adresse
/whois <nickname/user_address> = Sucht nach einem Benutzer anhand seines Namens oder seiner Adresse
/activitys = Benutzeraktivitäten anzeigen
/statistic or /stat = Gruppenstatistik anzeigen
/delivery or /message = Zustellungsstatus der letzten Nachricht anzeigen
/invite <user_address> = Lädt Benutzer zur Gruppe ein
```


## FAQ

### Warum diese serverbasierte Gruppenfunktion und keine direkten Gruppen in der Client-Software?
Zum Zeitpunkt der Entwicklung dieser Gruppenfunktionen gab es keine andere Möglichkeit, Gruppen über Sideband/Nomadnet zu verwenden. Daher wurde diese Software als Workaround entwickelt.
Diese Software bietet auch andere Funktionen als eine normale Gruppenübertragung.

### Wie kann ich mit der Software beginnen?
Sie sollten den Abschnitt `Installationsanleitung` lesen. Dort ist alles kurz erklärt. Gehen Sie einfach alles von oben nach unten durch :)