# QR-Scanner

Eigenstaendige macOS-App, die einen QR-Code ueber die Kamera liest, den Inhalt
in einem Textfeld anzeigt und ihn auf Wunsch in die Zwischenablage legt. Der
Inhalt wird **nicht** in eine Datei geschrieben.

Die App ist von Keep Vault unabhaengig: eigener Ordner, eigene Bundle-ID
(`de.michael-feinermann.qr-scanner`), eigene Signatur, eigener Build. Sie teilt
keinen Code mit Keep Vault, liest nichts aus dessen Bundle und wird von dessen
Build-Skript nicht angefasst. Reines Swift — der .NET-Werkzeugkasten von Keep
Vault wird nicht gebraucht.

## Bauen und installieren

```bash
./QrCodeScanner/tools/Build-QrScanner-macOS.sh \
  --version 4.0.2 --build-number 6 --install
```

Das Skript baut universell (arm64 + x86_64), fuehrt die Tests aus, erzeugt das
Icon, signiert mit Hardened Runtime und Sandbox, prueft die Signatur und legt
die App unter `/Applications/QR-Scanner.app` ab. Danach steht sie in Finder,
Launchpad und Spotlight und laesst sich per Doppelklick oeffnen.

Ohne `--install` bleibt das Ergebnis in `QrCodeScanner/dist/`.
Für ein gemeinsames Keep-Vault-Release müssen `--version` und
`--build-number` exakt den Werten des Keep-Vault-Builds entsprechen; der
portable Paket-Build lehnt fehlende oder abweichende Scanner-Metadaten ab.

Beim ersten Start fragt macOS einmal nach der Kamera. Wird die Frage verneint,
laesst sich das nur in den Systemeinstellungen unter „Datenschutz & Sicherheit“
› „Kamera“ zuruecknehmen — die App bekommt keine zweite Gelegenheit zu fragen
und sagt das auch.

## Welcher der beiden QR-Codes gilt

Ein Schluesselzettel traegt denselben Faktor in zwei QR-Codes. Das ist der
Grund fuer die Regel, und sie steht vollstaendig in
[`Sources/CodeArbiter.swift`](Sources/CodeArbiter.swift):

| Was die Kamera sieht | Was die App tut |
| --- | --- |
| Beide Codes lesbar, gleicher Inhalt | Sofort uebernommen — „durch 2 Codes bestaetigt“ |
| Ein Code beschaedigt, einer lesbar | Der lesbare gilt, nach 8 gleichen Lesungen in Folge |
| Beide Codes lesbar, **verschiedener** Inhalt | Nichts wird uebernommen, der Widerspruch wird gemeldet |
| Nichts lesbar | Weitersuchen |

Der entscheidende Punkt: „fehlerfrei“ ist nichts, was hinterher gemessen wird.
Ein QR-Code traegt Reed-Solomon-Parität, also liefert ein Decoder keinen
beschaedigten Inhalt — er repariert den Schaden und gibt das Original zurueck,
oder er scheitert und gibt gar nichts. Ein geknickter, verschmierter oder
angeschnittener Code taucht deshalb erst gar nicht unter den Treffern auf. Der
lesbare Code bleibt von allein uebrig.

Dass zwei gelesene Codes denselben Inhalt haben, wird geprueft und nicht
angenommen. Widersprechen sie sich, waere jede Wahl geraten — und geraten wird
hier die Haelfte eines Archivschluessels. Die App sagt es stattdessen.

Zwei Meldungen eines einzigen Codes im selben Bild zaehlen nicht als zwei
Codes: die Treffer werden nach Position gruppiert, sonst haette die staerkste
Bestaetigung der App eine doppelte Meldung als Grundlage.

### Gegen die echten Zettel geprueft

`tools/scan-file.swift` schickt eine PDF oder ein Bild durch genau denselben
Weg wie eine Kamerabild — gleiche Vision-Anfrage, gleiche `Detection`-Werte,
gleicher `CodeArbiter`:

```bash
xcrun swiftc -parse-as-library -O \
  QrCodeScanner/Sources/CodeArbiter.swift \
  QrCodeScanner/Sources/PayloadInspector.swift \
  QrCodeScanner/tools/scan-file.swift -o /tmp/scan-file
/tmp/scan-file ~/Downloads/mein-schluesselzettel.pdf
```

Auf den beiden Beispielzetteln: beide Codes gefunden, ein einziger
unterschiedlicher Inhalt, uebernommen als „durch 2 Codes bestaetigt“. Wird der
linke Code im Bild zerstoert, findet die App nur noch einen — und bekommt
denselben 128-stelligen Faktor heraus.

## Was die App nicht auf die SSD schreibt

Die App besitzt **kein** Datei-Entitlement, auch kein
`user-selected.read-only`. Sie hat nichts zu lesen und nichts zu schreiben, und
die Sandbox macht daraus eine Regel des Systems statt eines Versprechens des
Codes. Zusaetzlich sind die Wege abgeschaltet, auf denen AppKit von sich aus
Text auf die Platte bringt:

- **Fensterwiederherstellung.** `NSWindow.isRestorable = false` und
  `applicationSupportsSecureRestorableState → false`. Sonst legt AppKit den
  Fensterinhalt — hier also den gescannten Wert — unter
  `~/Library/Saved Application State/` ab.
- **Rechtschreibprüfung und Ersetzungen.** Der Prüfer lernt Woerter in das
  Benutzerwoerterbuch; die Ersetzungslogik fuehrt eigenen Zustand. Beides ist
  am Textfeld einzeln abgeschaltet.
- **Suchfenster.** `usesFindPanel = false`; die Suchhistorie landet sonst in den
  Defaults.
- **Datenerkennung.** Keine automatische Link- oder Datenerkennung, die Text an
  andere Dienste weiterreicht.
- **Protokolle.** Der Inhalt wird nirgends geloggt.

Nachgemessen nach einem Lauf: kein `~/Library/Saved Application State/`-Eintrag,
keine `~/Library/Preferences/de.michael-feinermann.qr-scanner.plist`.

## Was diese App nicht verhindern kann

Damit die Liste oben etwas wert ist, hier ehrlich das Gegenstueck.

- **Die Zwischenablage.** Der „Kopieren“-Knopf ist die eine Stelle, an der der
  Wert die App verlaesst. Die Zwischenablage gehoert dem System, nicht dieser
  App: macOS kann sie auf die Platte schreiben und ueber die universelle
  Zwischenablage an andere Apple-Geraete weitergeben. Kein Entitlement aendert
  das. Getan wird, was geht — der Eintrag wird als
  `org.nspasteboard.ConcealedType` markiert, den Zwischenablage-Verwalter
  respektieren, und nach **90 Sekunden** wieder geleert. Geleert wird nur, wenn
  in der Zwischenablage noch derselbe Wert steht; hat der Benutzer inzwischen
  etwas anderes kopiert, bleibt das unangetastet.
- **Der Sandbox-Container.** `~/Library/Containers/de.michael-feinermann.qr-scanner/`
  legt das System an, nicht die App. Darin erscheint ein Modell-Cache der
  Neural Engine (`com.apple.e5rt.e5bundlecache`), den das Vision-Framework beim
  ersten Lauf kompiliert. Das ist Framework-Maschinerie und enthaelt keinen
  gescannten Inhalt — aber es ist eine Datei, und deshalb steht sie hier.
- **Auslagerung und Absturzberichte.** Der Wert liegt im Arbeitsspeicher. Was
  macOS davon in den (verschluesselten) Auslagerungsbereich schreibt oder in
  einen Absturzbericht aufnimmt, entscheidet nicht die App.
- **Die Kamera sieht den Zettel.** Ein gedruckter Zettel vor einer Linse ist
  sichtbar — fuer die Kamera und fuer alles andere im Raum.

## Apple-Konformitaet

Die App ist sandboxed, laeuft unter dem Hardened Runtime und deklariert genau
zwei Entitlements: `app-sandbox` und `device.camera`. Ebenso wichtig ist, was
fehlt — `disable-library-validation`, `allow-unsigned-executable-memory`,
`allow-dyld-environment-variables`, `get-task-allow`. Jedes davon erlaubt einem
anderen Prozess, Code in diesen hier einzuschleusen, und dieser Prozess ist der,
der den gescannten Wert im Speicher haelt. Das Build-Skript bricht ab, wenn
eines davon in den Entitlements auftaucht **oder** in der fertigen Signatur
steht, und prueft danach, dass Sandbox, Kamera und Hardened Runtime wirklich
gesetzt sind.

Zum Zustand der Zertifizierung, ohne Beschoenigung: im Schluesselbund liegt
derzeit nur ein **Apple-Development**-Zertifikat. Damit laeuft die App auf
diesem Mac, aber `spctl --assess` weist sie ab und die Notarisierung nimmt sie
nicht an — der Notardienst akzeptiert ausschliesslich **Developer ID
Application**. Fuer eine App, die von diesem Rechner weitergegeben werden soll,
fehlt also das Zertifikat, nicht die Vorbereitung. Sobald es vorliegt:

```bash
xcrun notarytool store-credentials "QR-Scanner" \
  --apple-id DEINE-APPLE-ID --team-id TEAM-ID --password APP-SPEZIFISCHES-PASSWORT
./QrCodeScanner/tools/Build-QrScanner-macOS.sh --notary-profile "QR-Scanner" --install
```

Das Skript waehlt Developer ID automatisch, sobald es im Schluesselbund liegt,
notarisiert, heftet das Ticket an und prueft es mit `spctl` nach.

## Icon

Das Icon ist ein echter QR-Code auf einer abgerundeten Kachel und wird bei jedem
Build aus [`tools/make-icon.swift`](tools/make-icon.swift) erzeugt, statt als
Binaerdatei im Repository zu liegen. Er kodiert „QR-Scanner“ — wer ihn scannt,
bekommt genau das zurueck. Fehlerkorrektur L auf einer kurzen Zeichenkette haelt
die Modulzahl klein (Version 1), damit die Module auch bei 16 Punkten noch
einzeln sichtbar bleiben statt zu grauem Brei zu verlaufen.

## Aufbau

| Datei | Inhalt |
| --- | --- |
| `Sources/CodeArbiter.swift` | Die Regel, welcher der beiden Codes gilt. Ohne AppKit, damit sie testbar bleibt. |
| `Sources/PayloadInspector.swift` | Laengengrenze und Hinweise auf unsichtbare Zeichen im Inhalt. |
| `Sources/ScanSession.swift` | Kamera und Decodierung ueber Vision. |
| `Sources/VolatileClipboard.swift` | „Kopieren“ mit Verfallsfrist. |
| `Sources/MainWindowController.swift` | Fenster; enthaelt die Einstellungen gegen das Schreiben auf die Platte. |
| `Sources/App.swift` | Start, Menue, Zustandswiederherstellung abgelehnt. |
| `Tests/ArbiterTests.swift` | 26 Prüfungen der Regel; laufen bei jedem Build. |
| `tools/scan-file.swift` | Diagnose: dieselbe Auswertung auf eine Datei angewandt. |

## Warum die Erkennung nicht ueber AVCaptureMetadataOutput laeuft

Weil sie es auf macOS nicht kann. `AVCaptureMetadataOutput` liest
maschinenlesbare Codes nur unter iOS; unter macOS bietet dieselbe Klasse
Gesichtserkennung und sonst nichts. Der Fehler ist leicht zu machen, denn die
Klasse existiert auf macOS, laesst sich gegen `.qr` uebersetzen und meldet dann
einfach nie einen Code: `availableMetadataObjectTypes` enthaelt `.qr` nie, auch
nicht nachdem die Sitzung laeuft. Die Erkennung nutzt deshalb `Vision`
(`VNDetectBarcodesRequest`), das unter macOS funktioniert und ohnehin liefert,
was die Regel oben braucht — jeden Code im Bild einzeln, mit Inhalt und
Position.
