# Keep Vault

Anwendung zum Archivieren, Entpacken und kryptografischen Loeschen von ZPAQ-
Archiven, fuer **Windows** (WPF) und **macOS** (Avalonia). Beide Fassungen
teilen denselben Kryptografiekern und erzeugen dasselbe Containerformat, sodass
ein Archiv auf der jeweils anderen Plattform gelesen werden kann. Verschluesselte Archive koennen Kalyna-512/512 oder
Threefish-1024 verwenden. Beide Suites nutzen Argon2id aus den PHC-
Referenzquellen, HMAC-SHA3-512, Skeins nativen keyed MAC und zwei getrennt
erzeugte 512-Bit-Passwortfaktoren.

Die Anwendung befindet sich in Entwicklung. Sie ersetzt kein externes
Kryptografie-Audit, kein HSM und keine Betriebssystemhaertung.

## Installation

Fertige Pakete liegen unter
[Releases](https://github.com/alexanderfeinermann-a11y/keep-vault/releases).
Jedes Paket traegt neben Apples bzw. Authenticodes Signatur eine zweite,
unabhaengige Signatur aus RSA-PSS/SHA-512 und ML-DSA-87 (FIPS 204). Die
zugehoerigen `.sha3`-, `.skein`- und `.khsig`-Dateien gehoeren zum Paket und
duerfen nicht getrennt werden.

### Windows

1. `Keep Vault-portable-win-x64.zip` herunterladen.
2. Vor dem Entpacken in den Dateieigenschaften **Zulassen** setzen, sonst
   blockiert Windows die enthaltenen Programme.
3. ZIP entpacken.
4. `Install-KeepVaultShortcuts.ps1` in PowerShell ausfuehren, um Startmenue-
   und Desktop-Verknuepfungen anzulegen, oder `KalynaArchiver.exe` direkt
   starten.
5. Optional vorab pruefen:
   `"Keep Vault Release Verifier-win-x64.exe" "Keep Vault-portable-win-x64.zip"`

### macOS

Voraussetzung: macOS 14 oder neuer, Apple Silicon oder Intel (universelles
Binary).

1. `Keep Vault-portable-macOS.zip` herunterladen und entpacken.
2. Die Dateien `Keep Vault.app.launcher.*` gehoeren **neben** die App und
   muessen dort bleiben: der Launcher prueft bei jedem Start seine eigene duale
   Signatur und startet ohne diese Dateien nicht.
3. `tools/Install-KeepVault-macOS.sh` ausfuehren. Das Skript prueft die
   Signaturen, installiert nach `/Applications` und legt ein Alias auf dem
   Schreibtisch an. Es darf **nicht** mit `sudo` laufen.
4. Optional vorab pruefen:
   `"./Keep Vault Release Verifier" "Keep Vault.app"`

Beim Start prueft die App Apples Code-Signatur, die eingebetteten CDHash-Pins
und die duale Signatur jeder mitgelieferten ausfuehrbaren Datei. Schlaegt eine
dieser Pruefungen fehl, startet sie nicht.

Fuer das Einscannen der QR-Codes von den gedruckten Schluesselzetteln fragt
macOS beim ersten Mal nach Kamerazugriff. Die Kamera wird ausschliesslich vom
Hilfsprogramm `keep-vault-scanner` geoeffnet, nie vom Hauptprozess, und nur
fuer die Dauer eines Scans.

## Formatpolitik

Die App erzeugt und liest ausschliesslich das verschluesselte Containerformat
Version 7. Version 6 und aelter werden bewusst abgewiesen; ein Legacy-
Entschluesselungspfad ist nicht vorhanden.

Gemeinsame Eigenschaften:

- Magie `KZPAQ1\0`, UTF-8-JSON-Kopf, 64-Byte-HMAC-SHA3-512-Tag,
  128-Byte-Skein-1024-MAC-Tag und Chiffretext
- Passwortmodus `UserPassword+GeneratedHex512x2`
- KDF-Modus
  `SHA3-512-LP(UserPassword,FactorA)||SHA3-512-LP(UserPassword,FactorB)`
- 64-Byte-/512-Bit-Salt
- Argon2id 0x13 mit festem Produktionsprofil `m=1 GiB` (`1048576 KiB`),
  `t=4`, `p=4`
- Encrypt-then-MAC mit zwei getrennten Schluesseln und verpflichtender
  Verifikation beider Tags

Waehlt der User Kalyna, enthaelt der Kopf:

- `Kalyna-512/512-CTR+HMAC-SHA3-512+Skein-MAC-1024`
- 64-Byte-Kalyna-Schluessel, 64-Byte-HMAC-Schluessel und
  128-Byte-Skein-MAC-Schluessel
- 64-Byte-/512-Bit-Nonce und keinen Threefish-Tweak
- 256 Byte Argon2id-Ausgabe

Waehlt der User Threefish, enthaelt der Kopf:

- `Threefish-1024-CTR+HMAC-SHA3-512+Skein-MAC-1024`
- 128-Byte-Threefish-Schluessel, 64-Byte-HMAC-Schluessel und
  128-Byte-Skein-MAC-Schluessel
- 128-Byte-/1024-Bit-Nonce
- 16-Byte-/128-Bit-Tweak, domaenensepariert per SHA3-512 aus der Nonce abgeleitet
- 320 Byte Argon2id-Ausgabe

Der authentisierte Kopf bindet Version, Suite, Blockgroesse, Salt, Nonce,
Tweak, KDF-Modus, Argon2id-Profil, Ausgabelaenge und Passwortmodell. Beide MACs
umfassen dieselbe Magie, Kopflaenge, denselben Kopf und den gesamten Chiffretext.
Beide Tags werden vollstaendig und ohne Kurzschluss verglichen, bevor Klartext
in die ZPAQ-Pipe gelangt.

Der v7-Reader akzeptiert nur das feste Produktionsprofil `1 GiB / 4 / 4`.
Abweichende Kopfwerte werden vor der KDF verworfen, damit ein manipuliertes
Archiv weder schwaechere noch hoehere Argon2-Kosten erzwingen kann. Der native
Adapter erzwingt dasselbe Profil unabhaengig ein zweites Mal, vergroessert fuer
den KDF-Lauf kontrolliert das Windows-Working-Set und koordiniert diese
Reservierung mit den verwalteten `VirtualLock`-Puffern. Dadurch koennen
gleichzeitige GUI-/Mausereignisse die 1-GiB-Quote nicht waehrend der KDF
verkleinern. Der native Adapter
verlangt, dass `VirtualLock` die gesamte Argon2-Matrix sperrt. Scheitert diese
Sperre, bricht die KDF geschlossen ab; auslagerbarer Argon2-Arbeitsspeicher wird
nicht akzeptiert. Nach der KDF wird die Matrix vor `VirtualUnlock` und
`VirtualFree` vollstaendig genullt und die vorherige Working-Set-Konfiguration
wiederhergestellt.

Bei gesunden verschluesselten Archiven ersetzt der Dual-MAC-Prueflauf den separaten
vollstaendigen KPAR2-Vorabhash. Recovery wird nur bei beschaedigter Kennung/
Kopfzeile oder MAC-Fehler ausgefuehrt; nach erfolgreicher Reparatur erfolgt genau
ein neuer Authentifizierungs-/Entschluesselungsversuch. Dadurch benoetigt der
gesunde verschluesselte Pfad zwei statt drei vollstaendige Archiv-Lesepasses.

## Bedienung

Die GUI hat drei Tabs:

1. **Archive**: Dateien/Ordner auswaehlen oder ablegen, Ziel festlegen,
   Verschluesselung aktivieren und Threefish oder Kalyna waehlen. Threefish-1024
   steht an erster Stelle und ist die Werkseinstellung.
2. **Extract**: `.zpaq` oder `.kzpaq` ablegen; die Suite wird zunaechst aus dem
   noch unbestaetigten v7-Kopf angezeigt und vor jeder Klartextausgabe durch beide
   MACs authentisiert. Der Zielordner wird konfliktfrei vorgeschlagen.
   Extrahiert wird nur in einen neuen oder leeren Nicht-Reparse-Point-Ordner.
   Eine `.kzpaq` ohne gueltige Containerkennung und ohne nutzbares KPAR2-Sidecar
   wird geschlossen abgewiesen und niemals als unverschluesseltes ZPAQ an den
   nativen Parser weitergereicht.
3. **Cryptographic erase**: Einen gueltigen verschluesselten v7-Container
   analysieren, zuerst das rekonstruierbare Recovery-Sidecar entfernen und danach
   Kopf/Schluesselparameter sowie Container loeschen.

Vorgeschlagene Archiv- und Zielordnernamen erhalten mindestens `(1)`. Die
Standardsprache ist Englisch. Sprache, zuletzt gewaehlte Verschluesselungssuite
und ZPAQ-Kompressionsstufe werden als strikt validierte Komforteinstellungen im
Benutzerprofil gespeichert. Einstellungsdateien sind auf 64 Byte begrenzt;
ungueltige Werte fallen auf Englisch, Threefish beziehungsweise Kompressionsstufe 1
zurueck. Passwoerter, Zufallsfaktoren, Salt und Nonce werden dort nie abgelegt.
Beim Entpacken bestimmt weiterhin ausschliesslich der authentisierte Archivkopf
die Verschluesselungssuite; die gespeicherte GUI-Auswahl hat darauf keinen Einfluss.
Die Kompression ist Bestandteil des ZPAQ-Datenstroms und muss beim Entpacken nicht
erneut ausgewaehlt werden; die gespeicherte Stufe ist nur der Vorschlag fuer das
naechste neu erzeugte Archiv.
Erfolgreiche Archivierung beziehungsweise Extraktion leert die zugehoerigen
Passwort- und Faktor-Felder automatisch; beide Bereiche besitzen zusaetzlich
eine manuelle Schaltflaeche **Clear secrets**. Fehlgeschlagene Archivierungen
entfernen Teilarchive, Dualmanifeste und Recovery-Reste. Fehlgeschlagene oder
abgebrochene Extraktionen entfernen ihren partiellen Ausgabeordner.

## Passwortmodell

Zum Entpacken sind alle drei Werte erforderlich:

1. Userpasswort mit 24 bis 128 Zeichen.
2. Faktor A mit 128 Hexadezimalzeichen = 64 Byte = 512 Bit.
3. Faktor B mit 128 Hexadezimalzeichen = 64 Byte = 512 Bit.

Der Kopf speichert keinen dieser Werte. Er speichert nur oeffentliche,
notwendige Parameter wie Salt, Nonce, Tweak, Suite und Argon2id-Profil.
Der optionale Hinweis liegt ebenfalls oeffentlich im Kopf und darf keine
Passwortteile enthalten. Vor erfolgreicher MAC-Pruefung zeigt die GUI ihn
ausdruecklich als unbestaetigten Headertext an.

### Userpasswort-Richtlinie

Neue Archive verlangen:

- mindestens 24 und hoechstens 128 Zeichen
- mindestens 3 Zeichengruppen
- mindestens 12 verschiedene Zeichen
- mindestens 12 Zeichen ausserhalb `0-9`, `A-F`, `a-f`
- keine zusammenhaengende Hexadezimalfolge mit 8 oder mehr Zeichen
- keine Gleichheit mit Faktor A oder B
- Faktor A und Faktor B muessen voneinander verschieden sein
- mindestens 128 Bit konservative lokale Bewertung

Die GUI aktualisiert Bewertung und verletzte Bedingungen beim Tippen. Die
Bewertung begrenzt das angenommene Alphabet und bestraft Wiederholungen,
Sequenzen, Tastaturmuster und bekannte Begriffe. Sie ist eine pessimistische
Richtlinie, kein mathematischer Entropiebeweis fuer menschliche Passwoerter.

### Dual-SHA3-512 und Argon2id

Fuer jede Suite existieren getrennte Domains fuer A und B. `LP` bedeutet, dass
Domain, UTF-8-Userpasswort und normalisierter ASCII-Hex-Faktor jeweils ein
explizites 32-Bit-Laengenfeld erhalten. Danach berechnet die App:

```text
H_A = SHA3-512(LP(domain_A, userPassword, factorA))
H_B = SHA3-512(LP(domain_B, userPassword, factorB))
argonPassword = H_A || H_B                     # 128 Byte / 1024 Bit
```

`argonPassword` und der 64-Byte-Salt gehen unverkuerzt in Argon2id. Die
Ausgabelaenge ist 256 Byte fuer Kalyna beziehungsweise 320 Byte fuer Threefish.
Die Byte-Zielpuffer fuer UTF-8/ASCII-Kodierung, Laengenrahmen, beide SHA3-Hashes
und das zusammengesetzte `argonPassword` werden jeweils vor dem ersten
Schreibzugriff per `VirtualLock` gebunden. Nach Argon2id werden sie noch im
gesperrten Zustand genullt. Auch die aus der gesperrten Argon2-Ausgabe
abgetrennten Chiffre- und MAC-Schluessel werden nur in zuvor gesperrte Puffer
kopiert und dort vor dem Entsperren genullt.
Die App kompiliert direkt die unveraenderten PHC-Argon2-Kernquellen. Tests
vergleichen den nativen Adapter mit der PHC-CLI und den exakten 128-Byte-v7-Pfad
zusaetzlich mit Bouncy Castles unabhaengiger Argon2id-Implementierung.

Ein Salt verhindert vorab berechnete Tabellen fuer identisches Passwortmaterial.
Er macht ein schwaches Userpasswort allein nicht stark; die beiden unabhaengigen
Zufallsfaktoren und die speicherharte KDF liefern hier den wesentlichen Schutz.

## Zufall, Salt, Nonce und Tweak

Fuenf getrennte Pools sammeln Mausdaten fuer Faktor A, Faktor B, Salt, Nonce 1
und Nonce 2. Faktor- und Salt-Ausgaben sind jeweils das XOR aus:

- `BCryptGenRandom(..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)` als primaerer CSPRNG
- einer domaenenseparierten SHA3-512-Expansion des jeweiligen Mauspools

Die Nonce verwendet fuer beide Suites immer denselben 128-Byte-Quellpfad:

```text
H1 = SHA3-512(Nonce-1-Pool || Ableitungszaehler || Blockindex || Zweck)
H2 = SHA3-512(Nonce-2-Pool || Ableitungszaehler || Blockindex || Zweck)
R  = BCryptGenRandom(128 Byte, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
N  = R XOR (H1 || H2)
```

Threefish verwendet alle 128 Byte von `N`; Kalyna verwendet `N[0..63]`. Damit
ist die Erzeugungspipeline einheitlich. Wegen der abschliessenden Trunkierung
beeinflusst `H2` die ausgegebene Kalyna-Nonce mathematisch nicht; Kalynas 64 Byte
bleiben `R[0..63] XOR H1`.

Vor der gemeinsamen Archiventropie-Ausgabe benoetigt jeder Pool mindestens 512 Samples. Durch die
Rundlaufverteilung sind pro Entropie-Epoche mindestens 2560 Mausereignisse
erforderlich; die fuenf Zaehler unterscheiden sich dabei hoechstens um eins.
Die Anzahl beweist keine 512 Bit physikalische Mausentropie; Sicherheit darf
bereits auf `BCryptGenRandom` beruhen. Die Mausdaten sind nur zusaetzliche
Diversitaet.

Faktor A, Faktor B, Salt, Nonce 1 und Nonce 2 werden mit einem Klick gemeinsam
und atomar aus derselben Epoche, aber aus ihren fuenf getrennten Pools erzeugt.
Danach werden alle Pools ersetzt, im gesperrten Zustand genullt und ihre
aktuellen Zaehler auf null gesetzt. Null bedeutet in diesem Zustand daher
`verbraucht`, nicht `unzureichend`. Salt und der vollstaendige 128-Byte-Noncewert
bleiben bis zum Beginn der Verschluesselung ausschliesslich in gesperrtem RAM.
Beim ersten Verschluesselungsversuch werden sie genau einmal entnommen. Schlaegt
dieser Versuch nach der Entnahme fehl, bleiben A und B gueltig; fuer den
Wiederholungsversuch erzeugt die App aus einer frischen Epoche einen neuen Salt
und neue Nonces, damit niemals ein Nonce mit demselben Schluessel wiederverwendet
wird. Der in der GUI gezeigte Gesamtwert ist die Summe der aktuell noch nicht
verbrauchten Poolproben und kein historischer Lebenszeitzaehler.
Pool-Snapshots, Zaehlerrahmen, SHA3-Expansionsbloecke und CSPRNG-Zielpuffer
werden vor dem ersten Schreibzugriff gesperrt. Ersetzte Pools werden im
gesperrten Zustand genullt; Besitztransfers und Fehlerpfade werden durch die
Test-Suite gegen verbleibende `VirtualLock`-Leases geprueft.

Salt ist fuer beide Suites 64 Byte lang. Kalyna verwendet eine 64-Byte-Nonce,
Threefish eine 128-Byte-Nonce. Der oeffentliche 16-Byte-Threefish-Tweak wird
deterministisch und domaenensepariert aus der Threefish-Nonce abgeleitet und im
authentisierten Kopf gespeichert. Salt, Nonce und Tweak muessen nicht geheim sein.

## Schluesselzettel

Vor dem Verschluesseln muss die aktuelle Kombination aus Archivpfad, Suite und
beiden Faktoren gedruckt oder bewusst als Test-PDF exportiert werden.

- Standard ist der physische Druck ohne von der App erzeugte PDF-Datei.
- Offensichtliche virtuelle PDF-/XPS-/OneNote-/Fax-Drucker werden blockiert.
- Seitenfolge: Faktor A, wirklich leere Trennseite, Faktor B.
- Jede Geheimnisseite nennt Suite, Archivname/-pfad, genau einen Faktor, ein
  leeres handschriftliches Userpasswortfeld und den QR-Code dieses Faktors.
- A und B sollen getrennt und offline gelagert werden.
- **Save test PDF** schreibt beide Faktoren absichtlich dauerhaft auf den
  ausgewaehlten Datentraeger und ist kein sicherer Standardpfad.

Windows-Spooler, Treiber und Drucker koennen ausserhalb der App eigene temporaere
Daten anlegen.

## Streaming und Parallelisierung

ZPAQ liegt unter `external\zpaq`, Kalyna unter `external\Kalyna-reference` und die
offizielle Skein-1.3-/Threefish-Quelle unter `external\Skein-reference`.

Die angepasste ZPAQ-`--pipe`-Schnittstelle fuehrt das unverschluesselte ZPAQ-
Archiv direkt im RAM zwischen ZPAQ und dem Containerdienst. Es wird kein
unverschluesseltes Zwischenarchiv auf dem Datentraeger erzeugt. Der finale
Container wird zuerst unter einem zufaelligen Namen als bereits verschluesselter
Ciphertext geschrieben, auf den Datentraeger gespuelt und anschliessend atomar
ohne Ueberschreiben auf den Zielnamen verschoben.

Die lokale ZPAQ-Anpassung verwirft beim Entpacken absolute, UNC-/Drive- und
`..`-Pfade, Windows-ADS, mehrdeutige Punkt-/Leerzeichen-Enden sowie reservierte
Geraetenamen. Dadurch duerfen Archivmitglieder den leeren Zielordner nicht per
Pfad-Traversal verlassen. Der Erzeugungspfad laesst NTFS Alternate Data Streams
bewusst aus, damit die App weder versteckte Streams erzeugt noch Archive schreibt,
die ihr eigener gehaerteter Extraktor abweisen muesste. Die Extraktion erfolgt in
einem zufaelligen versteckten Schwesterordner und wird erst nach Erfolg per
Verzeichnis-Rename installiert.

Direkte Datei-Eingaben werden waehrend des gesamten ZPAQ-Aufrufs mit einem nicht
schreib-/loeschteilbaren Handle gebunden; Symlink-Aliase werden abgewiesen.
Archivziele duerfen weder mit einer Eingabe identisch sein noch innerhalb eines
eingelesenen Verzeichnisbaums liegen. Verifizierte Klartextarchive bleiben vom
Dualhash bis zum Ende des ZPAQ-Aufrufs ueber dasselbe kanonische Dateiobjekt
gesperrt. Der native ZPAQ-JIT ist deaktiviert; Modell-/Indexgroessen und
prozessseitige Diagnoseausgaben besitzen harte Grenzen.

Der angepasste Pipe-Extraktor arbeitet in einem einzigen Vorwaertspass und puffert
nicht das gesamte entschluesselte Archiv. Sein Speicherbedarf wird durch einen
ZPAQ-Block/ein Modell, die 16-MiB-Containerpuffer und Prozessmetadaten bestimmt,
nicht durch die Archivgroesse. Kurze Archivschreibvorgaenge, Pipefehler und
Seekfehler werden als harte Fehler behandelt.

`native\kalyna_ref_export.c` und `native\threefish_ref_export.c` teilen grosse
CTR-Aufrufe in disjunkte Block-/Counterbereiche fuer bis zu vier Worker. Die
Worker schreiben in disjunkte Ausgabebereiche; dadurch bleibt die Ausgabe
bitgenau identisch zum seriellen CTR-Pfad. Die Umgebungsvariablen
`KALYNA_CTR_THREADS` und `THREEFISH_CTR_THREADS` koennen 1 bis 4 Worker festlegen.
HMAC-SHA3-512 und Skein-MAC-1024 sind logisch sequenziell ueber denselben
resultierenden Chiffretext und werden in einem gemeinsamen Streaming-Pass
aktualisiert.

Der Threefish-Adapter nutzt die 80 Runden, Rotationen und Key-Schedule der
offiziellen `Skein1024_Process_Block`-Referenz unveraendert. Er entfernt nur den
Skein-UBI-Feedforward, um den rohen Threefish-Block zu erhalten. Tests pruefen den
offiziellen Skein-1.3-Golden-KAT, den offiziellen 128-Byte-keyed-MAC-KAT,
unabhaengige Bouncy-Castle-Vergleiche, Parallel-/Seriell-Aequivalenz und
CTR-Roundtrips.

CTR allein authentisiert nichts. Manipulationsschutz liefern gemeinsam der
HMAC-SHA3-512 mit 64-Byte-Schluessel/64-Byte-Tag und Skeins nativer keyed mode
mit 128-Byte-Schluessel/128-Byte-Tag. Beide Schluessel sind disjunkte Bereiche
der Argon2id-Ausgabe.

Unverschluesselte `.zpaq`-Archive erhalten stattdessen die verpflichtenden
Sidecars `<Archiv>.sha3` und `<Archiv>.skein`. Diese erkennen Korruption und
algorithmusspezifische Kollisionen, sind ohne privaten Signaturschluessel aber
kein Schutz gegen einen aktiven Angreifer, der Archiv und beide Sidecars ersetzt.

## Bitfehlerkorrektur

Zu jedem Archiv wird ein nicht abwaertskompatibles KPAR2-v2-Sidecar
`<Archivname>.kpar2` erstellt:

- Reed-Solomon `RS(20,3)`: 20 Daten- plus 3 Parity-Shards, 15 Prozent Overhead
- getrennte Parity-Bereiche fuer Kopf und Archivkoerper
- 4096-Byte-ausgerichtete Archiv-Shards und duale SHA3-512-/Skein-1024-Digests
- acht raeumlich getrennte, selbst dual gehashte 4096-Byte-Lokatoren: vier am
  Anfang, vier am Ende; mindestens fuenf identische gueltige Kopien sind Pflicht
- ein eigener Metadatenbereich aus exakt 4096 Byte grossen, selbst dual gehashten
  Bloecken; auch dieser Bereich ist stripeweise mit `RS(20,3)` geschuetzt
- das kanonische Manifest, beide Zertifikate/MAC-Tags, Suite, Salt,
  Argon2id-Profil und alle Shard-Digests liegen innerhalb dieses geschuetzten
  Metadatenbereichs

Damit bleiben Lokatoren, Manifest und beide Zertifikate auch beim vollstaendigen
Ausfall von bis zu drei beliebigen 4096-Byte-Bloecken rekonstruierbar. Einzelbits
und vollstaendig unlesbare 4-KiB-Bloecke im Archiv sind reparierbar, solange sie
pro Archiv-Stripe hoechstens drei Daten-Shards betreffen und noch mindestens so
viele gueltige Parity-Shards vorhanden sind. Vier ausgefallene Datenbloecke in
einem Stripe werden bewusst abgelehnt.

Blockorientierte `RandomAccess`-Lesezugriffe behandeln auch vom Dateisystem
gemeldete I/O-Lesefehler als Erasures. Beim Kopieren eines beschaedigten Archivs
faellt der Dienst nach einem fehlgeschlagenen grossen Lesezugriff auf 4096-Byte-
Leseeinheiten zurueck, markiert nur die unlesbaren Bloecke und rekonstruiert sie
im neuen Kandidaten. Daten- und Parity-Puffer werden pro Abschnitt einmal
angelegt und stripeweise wiederverwendet; der Arbeitsspeicherbedarf waechst daher
nicht mit der Archivgroesse.

Fuer **verschluesselte Archive** ist das KPAR2-Manifest immer zweifach
authentifiziert: HMAC-SHA3-512 und Skein-1024 keyed mode verwenden eigene,
domaenensepariert aus den disjunkten Archiv-MAC-Schluesseln und einer zufaelligen
Archiv-ID abgeleitete Recovery-Schluessel. Das authentifizierte Manifest bindet
die komplette Locator-Geometrie, Salt/Suite/KDF-Parameter, beide Archivdigests,
alle Daten-/Parity-Digests und deren Offsets. Falsche Passwortfaktoren oder eine
ausgetauschte KPAR2-Datei werden vor dem Erzeugen eines Reparaturkandidaten
abgelehnt.

Fuer **unverschluesselte Archive** sind dieselben SHA3-/Skein-Werte ausdruecklich
nur unkeyed Fehlererkennungswerte. Sie sind keine Signatur und bieten keine
Authentizitaet gegen einen Angreifer, der Archiv und Sidecars ersetzen kann. Eine
Reparatur wird deshalb immer in eine konfliktfrei benannte neue Datei geschrieben;
das beschaedigte Original bleibt unveraendert.

Der getrennte **Notfallmodus** ueberspringt die KPAR2-Metadaten-Authentifizierung,
schreibt ausnahmslos eine neue Datei und veraendert nie das Original. Bei einem
verschluesselten Archiv muessen trotzdem alle drei Passwortfaktoren vorliegen und
der fertige Kandidat muss die eingebetteten HMAC-SHA3-512- und Skein-1024-MACs des
Containers bestehen. Es gibt keinen automatischen Rueckfall vom normalen in den
Notfallmodus.

KPAR2 enthaelt bei verschluesselten Archiven nur Kopf- und Chiffretextparitaet,
keinen ZPAQ-Klartext. Cryptographic erase ueberschreibt und loescht auch das
Sidecar. Dabei werden Anfang und Ende zerstoert: am Anfang liegen saemtliche
Header-Parity-Shards, an beiden Enden die redundanten Lokatoren und am Ende der
Metadatenabschluss. Ein Vollueberschreiben eines bei 1 TB rund 150 GiB grossen
Sidecars waere auf SSDs weder physisch verlaesslich noch zweckmaessig.

## Integritaet und Signierung

Folgende native Laufzeitdateien brauchen Authenticode, eine hybride Signatur
`.khsig`, die kompilierten Schluesselpins und nach dem Signieren **beide**
Hashsidecars `.sha3` und `.skein`:

- `zpaq.exe`
- `argon2.exe`
- `argon2_ref.dll`
- `kalyna_ref.dll`
- `threefish_ref.dll`

Native Dateien werden nur neben der App oder in `tools` akzeptiert. Ein nicht
schreib-/loeschteilbares Handle haelt genau das gehashte und signaturgepruefte
Dateiobjekt bis zum Laden/Start gesperrt. Argon2, Kalyna und Threefish rufen ihre
Exporte direkt ueber Funktionszeiger aus genau diesem geprueften Modul-Handle auf;
eine zweite DLL-Namenssuche findet nicht statt. Geladene DLLs bleiben fuer die
Prozesslebensdauer durch Windows gebunden. Der vom gesperrten Handle aufgeloeste
finale DOS-Pfad muss exakt im erwarteten App-Verzeichnis liegen.

Die App-EXE wird ebenfalls gegen beide Manifeste, Authenticode und `.khsig`
geprueft. Bei einem nicht gebuendelten Build gilt das fuer jede lokale EXE/DLL
im App- und optionalen `tools`-Ordner, einschliesslich App-Assembly, Bouncy
Castle, PDFsharp und QRCoder. Im Portable-Single-File liegen die verwalteten
Abhaengigkeiten innerhalb der geprueften EXE. Das GUI bleibt gesperrt, bis alle
verpflichtenden Artefakte jede Pruefschicht erfuellen.

Authenticode verlangt genau eine primaere RSA-4096-Signatur mit
SHA-512-Dateidigest. Das Signaturzertifikat muss selbst mit RSA/SHA-512 signiert
sein, Digital-Signature-Key-Usage und Code-Signing-EKU besitzen. SignTool nutzt
auch fuer den RFC-3161-Zeitstempel SHA-512. Sekundaere Authenticode-Signaturen
werden blockiert, damit keine mehrdeutige Signerzuordnung entsteht.

Jedes signierte Artefakt besitzt zusaetzlich ein streng kodiertes `.khsig`-
Sidecar. Es bindet Domaene, Dateilaenge und SHA-512-Dateidigest und verlangt
gleichzeitig:

- RSA-PSS mit RSA-4096 und SHA-512
- ML-DSA-87 nach NIST FIPS 204

Beide Signaturen muessen gueltig sein; ein ODER-Rueckfall existiert nicht.
Abgeschnittene Sidecars, unbekannte Versionen und nachgestellte Daten werden
abgewiesen. Bei PE-Dateien muss der im Sidecar enthaltene RSA-Signer genau dem
primaeren Authenticode-Signer derselben Datei entsprechen.

RSA-SubjectPublicKeyInfo und roher ML-DSA-87-Public-Key sind jeweils dreifach
gepinnt:

- SHA-256
- SHA3-512
- Skein-1024

Alle sechs Fingerprints muessen exakt passen. Der Zertifikat-Thumbprint dient
nur als Build-Auswahl und zur Bindung von Authenticode an `.khsig`; er ist kein
konfigurierter Vertrauenspin. Mehrere Hashes addieren keine Sicherheitsbits,
vermeiden aber eine einzelne Hash-/Provider-Abhaengigkeit bei der
Schluesselidentifikation.

Windows Authenticode kennt derzeit keine ML-DSA-Signatur. Das Betriebssystem
validiert daher nur den RSA/SHA-512-Anteil; ML-DSA wird von der App und dem
separaten `KalynaReleaseVerifier` geprueft. Dies ist eine hybride
Anwendungssignatur und kein duales Windows-X.509-Zertifikat. ML-KEM-1024 aus
FIPS 203 ist ein KEM und kann keine Software signieren; fuer den
Post-Quanten-Signaturanteil wird deshalb ML-DSA-87 aus FIPS 204 verwendet.

Die importierten `pq-crystals/dilithium`-Referenzquellen sind auf Commit
`d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` festgelegt. Der Native-Build
verlangt fuer genau 21 einbezogene Referenzdateien passende SHA-256-,
SHA3-512- und Skein-1024-Quellmanifeste. Interoperabilitaetstests pruefen
verwaltete ML-DSA-87-Signaturen gegen diesen kompilierten Referenzadapter in
beiden Richtungen.

Die lokale Entwicklungs-PKI ist nur fuer Entwicklung geeignet:

- Root: `CN=Keep Vault Development Root SHA512`
- Leaf: `CN=Keep Vault Development Signing SHA512`
- Standard-Pins: `Directory.Build.props`

Das Signierskript verweigert `-TrustDevelopmentCertificate` und bricht ab,
falls die Entwicklungs-Root in `CurrentUser\Root` liegt. Die App akzeptiert die
nicht global vertraute Entwicklungssignatur nur ueber die sechs exakt
einkompilierten Fingerprints. Der RSA-Entwicklungsschluessel liegt nicht
exportierbar in `CurrentUser\My`; der ML-DSA-Entwicklungsschluessel liegt als
DPAPI-CurrentUser-Container vor. Prozesse mit denselben Benutzerrechten koennen
beide Signierpfade dennoch benutzen.

Eine oeffentliche Weitergabe braucht ein echtes RSA-Code-Signing-Zertifikat und
getrennt geschuetzte Produktionsschluessel fuer RSA und ML-DSA. Der aktuelle
lokale ML-DSA-Signieradapter ist ein Entwicklungs-Key-Store, kein HSM-Adapter.
Der externe Verifier und seine sechs Pins muessen ausserhalb des zu pruefenden
Pakets ueber einen authentisierten Kanal bezogen werden.

Die nativen Release-Artefakte werden mit statischer CRT, `/GS`, CFG
(`/guard:cf`), ASLR/NX und CET-Kompatibilitaet gebaut. Zur Laufzeit werden
Remote-/Low-Integrity-Images blockiert, `System32` bevorzugt und der allgemeine
DLL-Suchpfad auf `System32` begrenzt. Die aktuellen Importtabellen enthalten nur
Windows-System-DLLs.

Der verwaltete Build ist ueber `global.json` auf den geprueften
.NET-SDK-Featurestand und ueber den einheitlichen Restore-Graph auf `win-x64`
und Single-File-Publishing festgelegt. `packages.lock.json` bindet direkte und
transitive NuGet-Inhalte; Restore laeuft standardmaessig im Locked Mode. Nach
einer bewusst geprueften Paketaktualisierung muessen die Lockdateien explizit
mit `dotnet restore -p:RestoreLockedMode=false --force-evaluate` erneuert und
die vollstaendige Referenz- und Manipulationstestsuite wiederholt werden.

### Entwicklungsbuild

```powershell
.\tools\Build-Native.cmd
dotnet build .\KalynaArchiver\KalynaArchiver.csproj -c Release
& .\tools\Sign-Binaries.ps1 -Configuration Release -CreateDevelopmentCertificate
& .\tools\Generate-ReleaseManifests.ps1 -Configuration Release
& .\tools\Sign-ManagedOutput.ps1 -Configuration Release `
  -CertificateThumbprint '<Entwicklungs-Leaf-Thumbprint>'
```

### Release mit eigenen Schluesseln

```powershell
$certificate = '<40-stelliger Leaf-Thumbprint als Signierauswahl>'
$rsaSha256 = '<64-stelliger SHA-256-SPKI-Fingerprint>'
$rsaSha3 = '<128-stelliger SHA3-512-SPKI-Fingerprint>'
$rsaSkein = '<256-stelliger Skein-1024-SPKI-Fingerprint>'
$mlSha256 = '<64-stelliger SHA-256-ML-DSA-Fingerprint>'
$mlSha3 = '<128-stelliger SHA3-512-ML-DSA-Fingerprint>'
$mlSkein = '<256-stelliger Skein-1024-ML-DSA-Fingerprint>'
.\tools\Build-Native.cmd
dotnet build .\KalynaArchiver\KalynaArchiver.csproj -c Release `
  -p:KalynaExpectedSignerSha256=$rsaSha256 `
  -p:KalynaExpectedSignerSha3_512=$rsaSha3 `
  -p:KalynaExpectedSignerSkein1024=$rsaSkein `
  -p:KalynaExpectedMldsa87Sha256=$mlSha256 `
  -p:KalynaExpectedMldsa87Sha3_512=$mlSha3 `
  -p:KalynaExpectedMldsa87Skein1024=$mlSkein
& .\tools\Sign-Binaries.ps1 -Configuration Release `
  -CertificateThumbprint $certificate `
  -ExpectedSignerSha256 $rsaSha256 -ExpectedSignerSha3_512 $rsaSha3 `
  -ExpectedSignerSkein1024 $rsaSkein -ExpectedMldsa87Sha256 $mlSha256 `
  -ExpectedMldsa87Sha3_512 $mlSha3 -ExpectedMldsa87Skein1024 $mlSkein
```

## Portable Version

```powershell
& .\tools\Build-Portable.ps1 -CertificateThumbprint $certificate `
  -ExpectedSignerSha256 $rsaSha256 -ExpectedSignerSha3_512 $rsaSha3 `
  -ExpectedSignerSkein1024 $rsaSkein -ExpectedMldsa87Sha256 $mlSha256 `
  -ExpectedMldsa87Sha3_512 $mlSha3 -ExpectedMldsa87Skein1024 $mlSkein
```

Ausgabe sind `dist\Keep Vault-portable-win-x64` und die gleichnamige ZIP.

Desktop- und Startmenü-Verknüpfung für die lokale portable Ausgabe erstellen:

```powershell
pwsh -File ".\tools\Install-KeepVaultShortcuts.ps1"
```
Der Build kompiliert alle sechs Fingerprints ein, signiert App und native
Dateien und erzeugt danach SHA3-512-/Skein-1024-Manifeste sowie `.khsig` fuer
jedes Releaseartefakt. Auch ZIP, deren beide Hashmanifeste und der externe
Verifier werden hybrid signiert. `Keep Vault Release Verifier-win-x64.exe` prueft
wahlweise das entpackte Verzeichnis oder die ZIP vor dem Start.

## Sicherheitsgrenzen

- Sensible verwaltete Bytepuffer werden genullt und verpflichtend mit
  `VirtualLock` gegen Auslagerung gesperrt. Ein Lock- oder Working-Set-Fehler
  beendet die Operation. Das gilt ebenso fuer die gesamte native
  1-GiB-Argon2-Matrix.
- Prozesshaertung setzt best effort WER-, Fehler-, Handle- und Extension-Point-
  Mitigations sowie Image-Load- und DLL-Suchpfadregeln.
- `WDA_EXCLUDEFROMCAPTURE` wird angefordert, kann aber nicht jede Capture-
  Software, RDP-Konfiguration oder Hardwarekamera blockieren.
- WPF-Passwoerter existieren zeitweise als verwaltete Strings. Pagefile,
  Hibernation, Debugger, Malware mit Prozessrechten und Hardware-/Timing-Angriffe
  koennen von einer .NET-Desktop-App nicht vollstaendig ausgeschlossen werden.
- `VirtualLock` deckt nur die explizit gesperrten Puffer ab. CPU-Register,
  native Worker-Stacks und interner Zustand von Betriebssystem- oder
  Framework-Kryptografieprovidern koennen auf Anwendungsebene nicht verlaesslich
  gesperrt oder vollstaendig genullt werden.
- Threefish verwendet ARX-Operationen ohne geheime Tabellen. Die verwendete
  Kalyna-Referenz ist tabellenbasiert und bietet keinen beweisbaren Schutz gegen
  Cache-Seitenkanaele auf einem kompromittierten gemeinsam genutzten System.
- Ein 1024-Bit-Threefish-Schluessel und ein 1024-Bit-Skein-Tag bedeuten nicht,
  dass die Gesamtkonstruktion 1024 Bit Sicherheitsstaerke besitzt. KDF,
  Passwortmaterial, Chiffre, beide MACs und Implementierung begrenzen gemeinsam
  die reale Staerke; Sicherheitsbits werden nicht addiert.
- Duale unkeyed Hashes sind keine digitale Signatur. Die Release-Manifeste
  gewinnen aktive Faelschungsresistenz erst durch ihre verpflichtenden
  RSA-PSS-/ML-DSA-`.khsig`-Signaturen und den Schutz beider privaten Schluessel.
- Die hybride Codesignatur bleibt gegen einen kryptografisch relevanten
  Quantenangreifer nur dann faelschungsresistent, wenn ML-DSA-87, seine
  Implementierung und der ausserhalb des Pakets verankerte ML-DSA-Pin standhalten.
  RSA-4096 allein ist nicht post-quantenfest. Der AND-Verbund erlaubt jedoch
  keinen Rueckfall auf RSA, wenn nur RSA durch Shor gebrochen wird.
- SHA-256, SHA3-512 und Skein-1024 als parallele Pins addieren ihre
  Sicherheitsstaerken nicht. ML-DSA-87 besitzt NIST-Sicherheitskategorie 5;
  weder die App noch Bouncy Castle oder der lokale Referenzadapter sind dadurch
  automatisch FIPS-validierte Kryptomodule.
- `.khsig` besitzt keinen eigenen RFC-3161-Zeitstempel oder Sperrlistenstatus.
  Der Authenticode-Zeitstempel deckt nur die PE-Signatur ab. Langfristige
  Release-Archivierung muss daher Schluesselkompromittierungen und Pin-Rotation
  organisatorisch behandeln.
- Die lokalen Entwicklungs-Schluessel sind fuer Malware mit denselben
  Benutzerrechten verwendbar. Ein produktiver Build braucht zwei getrennt
  geschuetzte Signierschluessel und einen unabhaengig verteilten Verifier.
- Eine Selbstpruefung kann nicht erzwingen, dass ein vollstaendig ersetzter
  App-Bootstrap seinen eigenen Pruefcode ausfuehrt. Schutz vor diesem lokalen
  Startangriff erfordert zusaetzlich Windows Application Control/AppLocker und
  zwei fuer den Angreifer nicht nutzbare Release-Signierschluessel. Der externe
  Verifier hilft nur, wenn er selbst und seine Pins aus einer unabhaengig
  vertrauenswuerdigen Quelle stammen. Die Portable-Single-File-Ausgabe
  verkleinert lediglich die vorgelagerte Managed-DLL-Ladeflaeche.
- KPAR2 bietet Angreifer-Authentizitaet nur fuer verschluesselte Archive und nur
  nach erfolgreicher Pruefung beider domaenenseparierter Recovery-MACs. Das
  unverschluesselte Profil und der explizite Notfallmodus bieten lediglich
  Fehlerkorrektur; bei verschluesselten Notfallausgaben bleibt die nachgelagerte
  Container-Dual-MAC-Pruefung zwingend.
- `KPAR2` ist ein app-eigenes Format und nicht mit standardisierten PAR2-Werkzeugen
  kompatibel. Bei einem 1-TB-Archiv benoetigt 15 Prozent Redundanz ungefaehr
  150 GiB Sidecar-Speicher und mehrere vollstaendige Lese-/Schreibpasses.
- Per-Datei-Ueberschreiben garantiert auf SSDs keine physische Loeschung. Echte
  ATA/NVMe Secure Erase/Crypto Erase sind laufwerksweite Firmware-Aktionen.
- OneDrive/Cloud-Versionierung, Backups, Volume Shadow Copies und bereits
  vorhandene PDF-/Druckspoolerdateien koennen geloeschte Archive oder
  Schluesselzettel weiterhin enthalten.
- ZPAQ ist ein grosser nativer C++-Parser und laeuft derzeit nicht in einem
  AppContainer. Pfadtests, ein deterministischer Mutationskorpus, CFG/CET und
  Prozessbegrenzungen reduzieren das Risiko, ersetzen aber weder dauerhaftes
  Fuzzing noch ein unabhaengiges Audit des Parsers.
- Das Projekt zielt derzeit auf .NET 9. Diese STS-Version endet laut Microsoft am
  10. November 2026; vor diesem Datum ist eine getestete Migration auf .NET 10 LTS
  erforderlich.
- Ein physischer 1-TB-End-to-End-Test, eine formale Sicherheitsbeweisfuehrung und
  ein unabhaengiges externes Kryptografieaudit wurden nicht durchgefuehrt.

## Tests

```powershell
dotnet run --project .\KalynaArchiver.Tests\KalynaArchiver.Tests.csproj -c Release
```

Die Suite prueft GUI/Drag-and-drop, Spracherhaltung, Passwortregeln,
Entropiepools, getrennte Schluesselzettel, SHA3-512- und Skein-1024-KATs,
offizielle Skein-MAC-KATs, ML-DSA-87-Referenzinteroperabilitaet und
Manipulationen beider Hybrid-Signaturanteile, PHC- und Bouncy-Argon2id-
Vergleiche, Kalyna- und Threefish-Referenzvektoren, parallele CTR-
Aequivalenz, beide verschluesselten PDF-Roundtrips, falsche Faktoren,
Manipulation jedes einzelnen MAC-Tags, Klartext-Dualmanifeste, kurze Reads,
atomare Zielkonflikte, KPAR2-v2-Lokatorkonsens, dreifachen Ausfall von
Metadaten-/Zertifikatsbloecken, Vier-Block-Grenze, falsche Recovery-Faktoren,
Sidecar-Transplantation, Originalschutz im Notfallmodus, grosse Streamingdaten,
sechsfache RSA-/ML-DSA-Schluesselbindung, TOCTOU-Sperren,
Mehrfachsignatur-Sperre, NTFS-ADS-Konsistenz,
Argon2-Profil-Downgrades, KDF-Policy-Umgehungen, Archiv-Symlink-Aliase,
Eingabe-/Zielkonflikte, mutierte ZPAQ-Pipe-Eingaben und cryptographic erase.
Falls vorhanden wird
`C:\Users\Michael\OneDrive - tu-dortmund.de\Desktop\Aushang_Studienassistenz_2.pdf`
mit Poppler validiert. Ist nur die Datei mit dem Zusatz ` - Kopie.pdf` vorhanden,
wird diese stattdessen verwendet.

Quellen: [Kalyna reference](https://github.com/Roman-Oliynykov/Kalyna-reference),
[PHC Argon2](https://github.com/P-H-C/phc-winner-argon2),
[ZPAQ](https://github.com/zpaq/zpaq),
[FIPS 202 / SHA-3](https://csrc.nist.gov/pubs/fips/202/final),
[FIPS 204 / ML-DSA](https://csrc.nist.gov/pubs/fips/204/final),
[pq-crystals/dilithium](https://github.com/pq-crystals/dilithium),
[Threefish / Skein authors](https://www.schneier.com/academic/skein/threefish/),
[Skein 1.3 paper](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf),
[.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy),
[Windows process mitigations](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy).
