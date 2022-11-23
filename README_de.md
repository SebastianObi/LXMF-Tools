# LXMF-Tools
Verschiedene kleine Programme und Tools, die das Nachrichtenprotokoll LXMF verwenden von https://github.com/markqvist/LXMF


## lxmf_bridge_matrix
Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_bridge_matrix).


## lxmf_bridge_meshtastic
Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_bridge_meshtastic).


## lxmf_bridge_mqtt
Dieses Programm bietet eine Schnittstelle zwischen LXMF und MQTT. Es dient als Endpunkt für einzelne Nachrichten und nicht dazu, den LXMF/Reticlum-Verkehr 1:1 an MQTT zu übertragen. Es dient dem Zweck, einen Endpunkt im Reticulum-Netzwerk für Anwendungen von Drittanbietern bereitzustellen, die über MQTT kommunizieren können. Über diesen können alle LXMF-fähigen Anwendungen über Nachrichten mit ihm kommunizieren. Dies kann z.B. genutzt werden, um über Textnachrichten mit einem Smarthome-System (FHEM, openHAB, ioBroker, Node-RED o.ä.) zu kommunizieren. Das von MQTT verwendete Übertragungsformat ist JSON mit frei definierbaren Topics. Das Zielsystem kann dann auf diese JSON-Nachrichten antworten.


Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_bridge_mqtt).


## lxmf_bridge_telegram
Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_bridge_telegram).


## lxmf_chatbot
Dieses Programm bietet einen einfachen Chatbot (RiveScript), der über LXMF kommunizieren kann.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_chatbot).


## lxmf_cmd
Dieses Programm führt jeden per Nachricht empfangenen Text als Systembefehl aus und gibt die Ausgabe des Befehls als Nachricht zurück. Es können nur einzelne Befehle direkt ausgeführt werden. Es wird kein interaktives Terminal erzeugt.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_cmd).


## lxmf_distribution_group
Dieses Programm bietet eine E-Mail-ähnliche Verteilergruppe. Es verteilt eingehende LXMF-Nachrichten an mehrere Empfänger. Da dieses Programm wie ein normaler LXMF-Endpunkt agiert, können alle kompatiblen Chat-Anwendungen verwendet werden. Zusätzlich zum einfachen Messaging gibt es eine einfache kommandobasierte Benutzeroberfläche. Hier können alle relevanten Aktionen für die tägliche Verwaltung durchgeführt werden. Die Grundkonfiguration wird in den Konfigurationsdateien vorgenommen. Es gibt verschiedene Optionen, um das gesamte Verhalten der Gruppe an die eigenen Bedürfnisse anzupassen. Diese Verteilergruppe ist viel mehr als eine Standard-E-Mail-Verteilergruppe. Sie emuliert erweiterte Gruppenfunktionen mit automatischen Benachrichtigungen usw. Es können verschiedene Benutzerberechtigungen definiert werden. Für jeden Benutzertyp kann der Funktionsumfang individuell festgelegt werden. Die normalen Benutzer haben nur geringe Rechte. Während ein Moderator oder Admin mit einfachen Befehlen alles Notwendige erledigen kann. Ist die Grundkonfiguration einmal erledigt, kann alles Weitere über LXMF-Nachrichten als Befehle erfolgen.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_distribution_group).


## lxmf_distribution_group_minimal
Dieses Programm ist eine minimalistische Version der normalen Verteilungsgruppe. Die Funktionalität ist auf ein Minimum reduziert. Es können nur Absender und Empfänger definiert werden. Die Nachrichten werden dann entsprechend an die anderen Benutzer gesendet. Es gibt keine Benutzeroberfläche oder sonstige Benachrichtigungen. Lediglich die Nachrichten werden 1:1 verteilt. Die Verwaltung erfolgt komplett über die jeweiligen Konfigurationsdateien, die entsprechend zu bearbeiten sind.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_distribution_group_minimal).


## lxmf_echo
Dieses Programm ist ein einfacher Echo-Server. Alle empfangenen Nachrichten werden 1:1 als Antwort zurückgeschickt. Es kann als einfaches Gegenstück verwendet werden, um die Chat-Funktionalität von Anwendungen zu testen.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_echo).


## lxmf_ping
Dieses Programm sendet eine einstellbare Anzahl von LXMF-Nachrichten an ein Ziel. Anschließend wird eine einfache Statistik erstellt, um den Erfolg oder Misserfolg einer einzelnen Nachricht zu überprüfen. Dieses Tool kann nützlich sein, um das LXMF/Reticulum-Netzwerk mit einer bestimmten Anzahl von Nachrichten zu belasten. Damit lässt sich eine bestimmte Anzahl von Benutzern simulieren.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_ping).


## lxmf_terminal
Dieses Programm bietet eine vollständige Terminalsitzung auf dem Server. Es können beliebige Befehle auf dem Zielgerät ausgeführt werden. Die Kommunikation erfolgt über einzelne LXMF-Nachrichten. Dies bietet den Vorteil, dass einfache Terminalbefehle von jeder LXMF-fähigen Anwendung genutzt werden können.

Weitere Informationen finden Sie in der ausführlichen [README.md](lxmf_terminal).


## Allgemeine Informationen für alle Tools/Programme


### Aktueller Stand:
Es handelt sich derzeit um eine Betasoftware, die noch in Arbeit ist.

Alle Kernfunktionen sind implementiert und funktionieren, aber Ergänzungen werden wahrscheinlich auftreten, wenn die reale Nutzung erforscht wird.

Es kann zu Fehlern kommen oder die Kompatibilität nach einem Update ist nicht mehr gewährleistet.

Die vollständige Dokumentation ist noch nicht verfügbar. Aus Zeitmangel kann ich auch nicht sagen, wann diese weiterbearbeitet werden wird.


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
- Starten Sie
  ```bash
  ./lxmf_distribution_group.py
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.
- Beispiel einer Minimalkonfiguration (Überschreibung der Standardkonfiguration `config.cfg`). Dies sind die wichtigsten Einstellungen, die angepasst werden müssen. Alle anderen Einstellungen stehen in der `config.cfg`.
  ```bash
  nano /root/.lxmf_distribution_group/config.cfg.owr
  ```
- Starten Sie erneut. Fertig!
  ```bash
  ./lxmf_distribution_group.py
  ```


### Als Systemdienst/Dämon ausführen:
- Erstellen einer Servicedatei.
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


### Starten/Stopen des Dienstes:
  ```bash
  systemctl start lxmf_distribution_group
  systemctl stop lxmf_distribution_group
  ```


### Dienst aktivieren/deaktivieren:
  ```bash
  systemctl enable lxmf_distribution_group
  systemctl disable lxmf_distribution_group
  ```


### Mehrere Instanzen ausführen (Kopieren der gleichen Anwendung):
- Starten Sie das Programm mit einem anderen Konfigurationspfad.
  ```bash
  ./lxmf_distribution_group.py -p /root/.lxmf_distribution_group_2nd
  ./lxmf_distribution_group.py -p /root/.lxmf_distribution_group_3nd
  ```
- Nach dem ersten Start bearbeiten Sie die Konfigurationsdatei, um sie an Ihre Bedürfnisse und Ihren Anwendungsfall anzupassen. Der Speicherort der Datei wird angezeigt.


## Support / Donations
Sie können die weitere Entwicklung unterstützen, indem Sie über einen der folgenden Kanäle spenden:

- PayPal: https://paypal.me/SebastianObi
- Liberapay: https://liberapay.com/SebastianObi/donate


## Unterstützen Sie auf andere Weise?
Sie sind herzlich eingeladen, sich an der Entwicklung zu beteiligen. Erstellen Sie einfach einen Pull-Request. Oder kontaktieren Sie mich einfach für weitere Klärungen.


## Benötigen Sie eine spezielle Funktion oder Anpassung?
Dann nehmen Sie Kontakt mit mir auf. Speziell für Sie entwickelte Anpassungen oder Tools können realisiert werden.


## FAQ