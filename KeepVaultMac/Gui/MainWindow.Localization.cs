using Avalonia.Controls;
using KalynaArchiver.Services;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    /// <summary>
    /// Whether the app is currently being used in English.
    /// </summary>
    /// <remarks>
    /// Printed key sheets follow this rather than the machine locale: the sheet
    /// is read years later, and the language the owner chose in the app is the
    /// better guess at the language they will still read it in.
    /// </remarks>
    internal bool IsEnglish => _language == "en";

    private void ApplyLanguage()
    {
        Title = "Keep Vault";
        TitleText.Text = "Keep Vault";
        SubtitleText.Text = T("subtitle");
        LanguageLabel.Text = T("language");
        PopulateSuites();
        ArchiveTab.Header = T("archiveTab");
        ExtractTab.Header = T("extractTab");
        EraseTab.Header = T("eraseTab");
        ApplyIntegrityStatus();
        CaptureText.Text = T("captureUnavailable");
        PrivacyShieldText.Text = T("privacyShield");

        CreateTitleText.Text = T("createTitle");
        CreateSubtitleText.Text = T("createSubtitle");
        AddFilesButton.Content = T("addFiles");
        AddFolderButton.Content = T("addFolder");
        ClearInputsButton.Content = T("clearSelection");
        InputDropHintText.Text = T("inputDropHint");
        TargetArchiveLabel.Text = T("targetArchive");
        TargetArchiveDropHintText.Text = T("targetArchiveDropHint");
        BrowseArchiveButton.Content = T("browse");
        CompressionLabel.Text = T("compression");
        EncryptBox.Content = T("encrypt");
        CipherSuiteLabel.Text = T("cipherSuite");
        Argon2ProfileText.Text = T("argon2Profile");
        DeleteOriginalsBox.Content = T("deleteOriginals");
        DeleteOriginalsHint.Text = T("deleteOriginalsHint");
        CreateArchiveButton.Content = T("saveArchive");
        CreatePasswordSetupTitle.Text = T("createPasswordTitle");
        CreatePasswordSetupHelpText.Text = T("createPasswordHelp");
        CreatePasswordLabel.Text = T("userPassword");
        CreatePasswordConfirmLabel.Text = T("repeatPassword");
        CreatePinLabel.Text = T("pin");
        CreatePinConfirmLabel.Text = T("repeatPin");
        PinHelpText.Text = T("pinHelp");
        PasswordHelpText.Text = T("passwordHelp");
        PasswordGeneratorTitle.Text = T("generatorTitle");
        PasswordGeneratorHelpText.Text = T("generatorHelp");
        GeneratedPasswordFirstLabel.Text = T("factorA");
        GeneratedPasswordSecondLabel.Text = T("factorB");
        PrintKeySheetButton.Content = T("printKeySheets");
        SaveKeySheetButton.Content = T("saveTestPdf");
        ClearCreateSecretsButton.Content = T("clearSecrets");
        KeySheetStatusText.Text = _keySheetFingerprint is null ? T("keySheetMissing") : T("keySheetHandled");
        HintLabel.Text = T("optionalHint");
        HintWarningText.Text = T("hintWarning");

        ExtractTitleText.Text = T("extractTitle");
        ExtractSubtitleText.Text = T("extractSubtitle");
        RecoveryPolicyText.Text = T("recoveryPolicy");
        ArchiveFileLabel.Text = T("archiveFile");
        ExtractArchiveDropHintText.Text = T("extractDropHint");
        BrowseExtractArchiveButton.Content = T("browse");
        OutputFolderLabel.Text = T("outputFolder");
        OutputFolderDropHintText.Text = T("outputDropHint");
        BrowseOutputFolderButton.Content = T("browse");
        ExtractArchiveButton.Content = T("extract");
        ListArchiveButton.Content = T("listContents");
        EmergencyRecoveryButton.Content = T("emergencyRecovery");
        ClearExtractSecretsButton.Content = T("clearSecrets");
        ExtractPasswordTitle.Text = T("extractPasswordTitle");
        ExtractPasswordHelpText.Text = T("extractPasswordHelp");
        ExtractHintLabel.Text = T("extractHintLabel");
        ExtractPasswordLabel.Text = T("userPassword");
        ExtractPinLabel.Text = T("pin");
        ExtractGeneratedPasswordFirstLabel.Text = T("factorAFromSheet");
        ExtractGeneratedPasswordSecondLabel.Text = T("factorBFromSheet");
        RenderExtractHint();

        EraseTitleText.Text = T("eraseTitle");
        EraseSubtitleText.Text = T("eraseSubtitle");
        EraseFileLabel.Text = T("eraseFile");
        EraseDropHintText.Text = T("eraseDropHint");
        BrowseEraseButton.Content = T("browse");
        AnalyzeEraseButton.Content = T("analyze");
        if (EraseStatusText.Text is "Noch keine Datei analysiert." or "No file analyzed yet.")
        {
            EraseStatusText.Text = T("eraseNotAnalyzed");
        }

        EraseHardwareNoticeText.Text = T("eraseHardwareNotice");
        EraseConfirmBox.Content = T("eraseConfirm");
        EraseContainerButton.Content = T("eraseButton");
        LogTitleText.Text = T("securityLog");
        ClearLogButton.Content = T("clear");
        OperationStatusText.Text = Volatile.Read(ref _operationActive) != 0 ? T("working") : _integrityTrusted ? T("ready") : T("blocked");
        UpdateEntropyStatus(force: true);
        UpdatePasswordPolicyStatus();
    }

    private string T(string key)
    {
        bool en = IsEnglish;
        return key switch
        {
            "subtitle" => en ? "Secure, recoverable archives for macOS" : "Sichere, wiederherstellbare Archive für macOS",
            "language" => en ? "Language" : "Sprache",
            "archiveTab" => en ? "Archive" : "Archivierung",
            "extractTab" => en ? "Extract" : "Entpacken",
            "eraseTab" => en ? "Cryptographic erase" : "Kryptografisch löschen",
            "integrityChecking" => en ? "Checking integrity …" : "Integrität wird geprüft …",
            "integrityOk" => en ? "Integrity check passed" : "Integritätsprüfung bestanden",
            "integrityWarning" => en ? "Integrity violation: operations blocked" : "Integritätsverletzung: Aktionen gesperrt",
            "integrityFailed" => en ? "Integrity check failed" : "Integritätsprüfung fehlgeschlagen",
            "captureUnavailable" => en ? "Capture protection: best effort only" : "Aufnahmeschutz: nur bestmöglich",
            "privacyShield" => en
                ? "Secret content is concealed while Keep Vault is not the active application."
                : "Geheimnisinhalte werden verdeckt, solange Keep Vault nicht die aktive App ist.",
            "captureBoundaryLog" => en
                ? "macOS does not provide a reliable application-level exclusion from screenshots or screen recording. Sensitive windows are concealed on deactivation where possible, but capture prevention cannot be guaranteed."
                : "macOS bietet keinen verlässlichen App-Ausschluss für Screenshots oder Bildschirmaufnahmen. Geheimnisansichten werden soweit möglich bei Deaktivierung verdeckt, ein Aufnahmeschutz kann jedoch nicht garantiert werden.",
            "createTitle" => en ? "Create archive" : "Archiv erstellen",
            "createSubtitle" => en
                ? "Select files or folders, choose a new target, and handle both separate key sheets before encryption."
                : "Dateien oder Ordner auswählen, ein neues Ziel festlegen und vor der Verschlüsselung beide getrennten Schlüsselzettel behandeln.",
            "addFiles" => en ? "Add files" : "Dateien hinzufügen",
            "addFolder" => en ? "Add folder" : "Ordner hinzufügen",
            "clearSelection" => en ? "Clear selection" : "Auswahl leeren",
            "inputDropHint" => en ? "Drop files or folders anywhere in this panel." : "Dateien oder Ordner irgendwo in diesem Panel ablegen.",
            "targetArchive" => en ? "Target archive" : "Zielarchiv",
            "targetArchiveDropHint" => en
                ? "Drop a folder to create folder(1).kzpaq beside it, or a file to derive name(1).kzpaq."
                : "Ordner ablegen, um daneben ordner(1).kzpaq zu erzeugen, oder eine Datei für name(1).kzpaq ablegen.",
            "browse" => en ? "Browse" : "Auswählen",
            "compression" => en ? "Compression" : "Kompression",
            "encrypt" => en ? "Encrypt archive" : "Archiv verschlüsseln",
            "cipherSuite" => en ? "Cipher suite" : "Verfahren",
            "argon2Profile" => en
                ? "Two sequential KDF paths (1 GiB to just under 2 GiB via PMI16, t=4, p=4) with shared 1024-bit master (Paranoia: 4 Argon2id passes, locked RAM required)"
                : "Zwei sequenzielle KDF-Pfade (1 GiB bis knapp 2 GiB via PMI16, t=4, p=4) mit gemeinsamem 1024-Bit-Master (Paranoia: 4 Argon2id-Aufrufe, gesperrter RAM erforderlich)",
            "deleteOriginals" => en
                ? "Delete original files after a verified comparison"
                : "Originaldateien nach geprüftem Abgleich löschen",
            "deleteOriginalsHint" => en
                ? "The archive is then extracted again and compared byte-for-byte with the original files. Files are deleted only after a complete match."
                : "Das Archiv wird danach erneut entpackt und bitweise mit den Originalen verglichen. Gelöscht wird erst bei vollständiger Übereinstimmung.",
            "saveArchive" => en ? "Save archive" : "Archiv speichern",
            "createPasswordTitle" => en ? "Four-part password" : "Vierteiliges Passwort",
            "createPasswordHelp" => en
                ? "Extraction requires the user password, the PIN and both independently generated factors A and B. All four are mandatory."
                : "Zum Entpacken werden Userpasswort, PIN sowie beide unabhängig generierten Faktoren A und B benötigt. Alle vier sind zwingend.",
            "userPassword" => en ? "User password" : "Userpasswort",
            "repeatPassword" => en ? "Repeat user password" : "Userpasswort wiederholen",
            "passwordHelp" => en
                ? "24 to 256 characters, at least 3 character groups, 12 distinct and 12 non-hex characters, no hex run of 8+, and at least 128 conservative entropy bits."
                : "24 bis 256 Zeichen, mindestens 3 Zeichengruppen, 12 verschiedene und 12 Nicht-Hex-Zeichen, keine Hex-Folge ab 8 Zeichen und mindestens 128 Bit konservative Bewertung.",
            "generatorTitle" => en ? "Two independent 1024-bit factors" : "Zwei unabhängige 1024-Bit-Faktoren",
            "generatorHelp" => en
                ? $"Nine separate entropy pools need at least {EntropyMixer.RequiredMouseSamplesPerPurpose} mouse samples each. Generation atomically creates factors A and B, both salts and all three nonce parts, then consumes all source pools."
                : $"Neun getrennte Entropiepools benötigen je mindestens {EntropyMixer.RequiredMouseSamplesPerPurpose} Maus-Samples. Generieren erzeugt die Faktoren A und B, beide Salts und alle drei Nonce-Teile atomar und verbraucht danach alle Quellpools.",
            "factorA" => en ? "Generated factor A" : "Generierter Faktor A",
            "factorB" => en ? "Generated factor B" : "Generierter Faktor B",
            "printKeySheets" => en ? "Print separately" : "Getrennt drucken",
            "saveTestPdf" => en ? "Save test PDF" : "Test-PDF speichern",
            "clearSecrets" => en ? "Clear secrets" : "Geheimwerte leeren",
            "optionalHint" => en ? "Optional hint" : "Optionaler Hinweis",
            "hintWarning" => en
                ? "Stored in the public container header. Never enter passwords or secret fragments."
                : "Wird im öffentlichen Containerkopf gespeichert. Niemals Passwörter oder Geheimnisfragmente eingeben.",
            "generatePassword" => en ? "Generate" : "Generieren",
            "regeneratePassword" => en ? "Regenerate" : "Neu generieren",
            "pin" => en ? "PIN" : "PIN",
            "repeatPin" => en ? "Repeat PIN" : "PIN wiederholen",
            "pinHelp" => en
                ? "6 to 16 digits. The PIN is a credential of its own and is required together with the passphrase and both factors."
                : "6 bis 16 Ziffern. Die PIN ist ein eigener Faktor und wird zusammen mit dem Passwort und beiden Faktoren benötigt.",
            "pinInvalid" => en
                ? "The PIN must consist of {0} to {1} digits."
                : "Die PIN muss aus {0} bis {1} Ziffern bestehen.",
            "pinMismatch" => en
                ? "Both PIN entries differ."
                : "Beide PIN-Eingaben unterscheiden sich.",
            "pinAccepted" => en
                ? "PIN accepted."
                : "PIN akzeptiert.",
            "pinTooShort" => en ? "Use at least {0} digits." : "Mindestens {0} Ziffern verwenden.",
            "pinTooLong" => en ? "Use no more than {0} digits." : "Höchstens {0} Ziffern verwenden.",
            "pinNonDigit" => en ? "The PIN must consist of digits only." : "Die PIN darf nur aus Ziffern bestehen.",
            "pinDistinct" => en ? "Use at least {0} distinct digits." : "Mindestens {0} verschiedene Ziffern verwenden.",
            "pinRepeatedTriple" => en ? "Do not repeat the same digit 3 or more times consecutively." : "Keine 3 gleichen Ziffern hintereinander verwenden.",
            "pinSequentialAscending" => en ? "Do not use 3 or more ascending consecutive digits." : "Keine 3 aufsteigenden Ziffernfolgen verwenden.",
            "pinSequentialDescending" => en ? "Do not use 3 or more descending consecutive digits." : "Keine 3 absteigenden Ziffernfolgen verwenden.",
            "pinBlocklisted" => en ? "This PIN pattern is too predictable." : "Dieses PIN-Muster ist leicht erratbar.",
            "entropyCollecting" => en
                ? "Collecting: total {0}; A {1}+{2}/{10}; B {3}+{4}/{10}; salt-SHA3 {5}/{10}; salt-Skein {6}/{10}; nonce 1 {7}/{10}; nonce 2 {8}/{10}; nonce 3 {9}/{10}"
                : "Sammlung: gesamt {0}; A {1}+{2}/{10}; B {3}+{4}/{10}; Salt-SHA3 {5}/{10}; Salt-Skein {6}/{10}; Nonce 1 {7}/{10}; Nonce 2 {8}/{10}; Nonce 3 {9}/{10}",
            "entropyPrepared" => en
                ? "Ready and source pools consumed. Fresh pools: total {0}; A {1}+{2}/{10}; B {3}+{4}/{10}; salt-SHA3 {5}/{10}; salt-Skein {6}/{10}; nonce 1 {7}/{10}; nonce 2 {8}/{10}; nonce 3 {9}/{10}"
                : "Bereit und Quellpools verbraucht. Frische Pools: gesamt {0}; A {1}+{2}/{10}; B {3}+{4}/{10}; Salt-SHA3 {5}/{10}; Salt-Skein {6}/{10}; Nonce 1 {7}/{10}; Nonce 2 {8}/{10}; Nonce 3 {9}/{10}",
            "entropyRetry" => en
                ? "Factors remain valid; a retry needs fresh salts and nonces: total {0}; A {1}+{2}/{10}; B {3}+{4}/{10}; salt-SHA3 {5}/{10}; salt-Skein {6}/{10}; nonce 1 {7}/{10}; nonce 2 {8}/{10}; nonce 3 {9}/{10}"
                : "Faktoren bleiben gültig; ein Wiederholungsversuch benötigt frische Salts und Nonces: gesamt {0}; A {1}+{2}/{10}; B {3}+{4}/{10}; Salt-SHA3 {5}/{10}; Salt-Skein {6}/{10}; Nonce 1 {7}/{10}; Nonce 2 {8}/{10}; Nonce 3 {9}/{10}",
            "passwordEntropy" => en ? "Password strength estimate: {0:0.0} / {1:0} bits" : "Passwortstärke-Schätzwert: {0:0.0} / {1:0} Bit",
            "passwordAccepted" => en ? "All user-password requirements are met." : "Alle Anforderungen an das Userpasswort sind erfüllt.",
            "passwordTooShort" => en ? "Use at least {0} characters." : "Mindestens {0} Zeichen verwenden.",
            "passwordTooLong" => en ? "Use no more than {0} characters." : "Höchstens {0} Zeichen verwenden.",
            "passwordControl" => en ? "Remove control characters." : "Steuerzeichen entfernen.",
            "passwordUnicode" => en ? "Remove malformed Unicode." : "Ungültiges Unicode entfernen.",
            "passwordClasses" => en ? "Use at least 3 character groups." : "Mindestens 3 Zeichengruppen verwenden.",
            "passwordDistinct" => en ? "Use at least 12 distinct characters." : "Mindestens 12 verschiedene Zeichen verwenden.",
            "passwordNonHex" => en ? "Use at least 12 non-hex characters." : "Mindestens 12 Nicht-Hex-Zeichen verwenden.",
            "passwordHexRun" => en ? "Break every hexadecimal run before 8 characters." : "Jede Hex-Folge vor 8 Zeichen unterbrechen.",
            "passwordMatchesFactor" => en ? "Do not reuse either generated factor." : "Keinen generierten Faktor als Userpasswort verwenden.",
            "passwordLowEntropy" => en ? "Increase the password strength estimate to at least 128." : "Passwortstärke-Schätzwert auf mindestens 128 erhöhen.",
            "passwordInvalid" => en ? "The user password is not accepted." : "Das Userpasswort wird nicht akzeptiert.",
            "keySheetMissing" => en
                ? "The two key sheets have not been physically printed or explicitly exported for testing."
                : "Die zwei Schlüsselzettel wurden noch nicht physisch gedruckt oder ausdrücklich zum Test exportiert.",
            "keySheetHandled" => en
                ? "The key sheets were handled for this exact archive path, suite and factor pair."
                : "Die Schlüsselzettel wurden für exakt diesen Archivpfad, dieses Verfahren und dieses Faktorenpaar behandelt.",
            "extractTitle" => en ? "Extract archive" : "Archiv entpacken",
            "extractSubtitle" => en ? "Select a ZPAQ archive or encrypted Keep Vault container." : "ZPAQ-Archiv oder verschlüsselten Keep-Vault-Container auswählen.",
            "recoveryPolicy" => en
                ? "KPAR2 authenticates encrypted archives with two keyed MACs. For plain archives it only provides error correction. Emergency recovery always writes a new file."
                : "KPAR2 authentifiziert verschlüsselte Archive mit zwei MACs. Für unverschlüsselte Archive bietet es nur Fehlerkorrektur. Die Notfallwiederherstellung schreibt immer eine neue Datei.",
            "archiveFile" => en ? "Archive file" : "Archivdatei",
            "extractDropHint" => en ? "Drop a .zpaq or .kzpaq file here." : ".zpaq- oder .kzpaq-Datei hier ablegen.",
            "outputFolder" => en ? "New output folder" : "Neuer Ausgabeordner",
            "outputDropHint" => en
                ? "Choose or drop its parent folder. Keep Vault proposes a new subfolder inside it."
                : "Übergeordneten Ordner auswählen oder ablegen. Keep Vault schlägt darin einen neuen Unterordner vor.",
            "extract" => en ? "Extract" : "Entpacken",
            "listContents" => en ? "Show contents" : "Inhalt anzeigen",
            "emergencyRecovery" => en ? "Emergency recovery" : "Notfallwiederherstellung",
            "extractPasswordTitle" => en ? "Three factors for extraction" : "Drei Faktoren zum Entpacken",
            "extractPasswordHelp" => en
                ? "Enter the user password, the PIN and both factors from the separately stored key sheets."
                : "Userpasswort, PIN und beide Faktoren von den getrennt gelagerten Schlüsselzetteln eingeben.",
            "extractHintLabel" => en ? "Public archive hint" : "Öffentlicher Archivhinweis",
            "factorAFromSheet" => en ? "Factor A from key sheet" : "Faktor A vom Schlüsselzettel",
            "factorBFromSheet" => en ? "Factor B from key sheet" : "Faktor B vom Schlüsselzettel",
            "hintNotLoaded" => en ? "No container hint loaded." : "Noch kein Containerhinweis geladen.",
            "hintNone" => en ? "The container has no hint." : "Der Container enthält keinen Hinweis.",
            "hintUnavailable" => en ? "The public hint could not be read." : "Der öffentliche Hinweis konnte nicht gelesen werden.",
            "hintUnverified" => en ? "Unverified public-header hint: {0}" : "Unbestätigter öffentlicher Kopf-Hinweis: {0}",
            "eraseTitle" => en ? "Cryptographic erase" : "Kryptografisch löschen",
            "eraseSubtitle" => en
                ? "Destroy recovery data first, then corrupt and delete the encrypted container."
                : "Zuerst Wiederherstellungsdaten vernichten, danach den verschlüsselten Container beschädigen und löschen.",
            "eraseFile" => en ? "Encrypted container" : "Verschlüsselter Container",
            "eraseDropHint" => en ? "Drop an encrypted .kzpaq container here." : "Verschlüsselten .kzpaq-Container hier ablegen.",
            "analyze" => en ? "Analyze" : "Analysieren",
            "eraseNotAnalyzed" => en ? "No file analyzed yet." : "Noch keine Datei analysiert.",
            "eraseHardwareNotice" => en
                ? "This invalidates the current local container file only. APFS snapshots, Time Machine backups, cloud copies, and physical SSD flash remanence are not removed."
                : "Dies macht nur die aktuelle lokale Containerdatei unbrauchbar. APFS-Snapshots, Time-Machine-Backups, Cloud-Versionen und SSD-Flash-Remanenz werden dadurch nicht gelöscht.",
            "eraseConfirm" => en
                ? "I understand that APFS snapshots/backups are not erased and want to delete this container."
                : "Ich verstehe, dass APFS-Snapshots/Backups nicht gelöscht werden, und möchte diesen Container löschen.",
            "eraseButton" => en ? "Cryptographically erase container" : "Container kryptografisch löschen",
            "securityLog" => en ? "Security log" : "Sicherheitsprotokoll",
            "clear" => en ? "Clear" : "Leeren",
            "ready" => en ? "Ready" : "Bereit",
            "blocked" => en ? "Blocked until trusted" : "Bis zur Freigabe gesperrt",
            "working" => en ? "Protected operation running …" : "Geschützte Aktion läuft …",
            "noticeTitle" => en ? "Keep Vault" : "Keep Vault",
            "errorTitle" => en ? "Error" : "Fehler",
            "confirmationTitle" => en ? "Confirm protected action" : "Geschützte Aktion bestätigen",
            "ok" => en ? "OK" : "OK",
            "continue" => en ? "Continue" : "Fortfahren",
            "cancel" => en ? "Cancel" : "Abbrechen",
            "print" => en ? "Print" : "Drucken",
            "selectPrinter" => en ? "Select a physical printer" : "Physischen Drucker auswählen",

            "chooseFilesDialog" => en ? "Select files for the archive" : "Dateien für das Archiv auswählen",
            "chooseFolderDialog" => en ? "Select a folder for the archive" : "Ordner für das Archiv auswählen",
            "saveArchiveDialog" => en ? "Choose the destination folder for the new archive" : "Zielordner für das neue Archiv auswählen",
            "chooseArchiveDialog" => en ? "Select an archive" : "Archiv auswählen",
            "chooseOutputDialog" => en ? "Choose the parent folder for the new output folder" : "Übergeordneten Ordner für den neuen Ausgabeordner auswählen",
            "chooseEraseDialog" => en ? "Select encrypted container" : "Verschlüsselten Container auswählen",
            "chooseArchiveDestinationFolderDialog" => en ? "Allow access to the archive destination folder" : "Zugriff auf den Zielordner des Archivs erlauben",
            "chooseArchiveSidecarFolderDialog" => en ? "Allow access to the archive folder and its recovery files" : "Zugriff auf den Archivordner und seine Wiederherstellungsdateien erlauben",
            "chooseOutputParentDialog" => en ? "Allow access to the parent of the new output folder" : "Zugriff auf den übergeordneten Ordner des neuen Ausgabeordners erlauben",
            "chooseEraseSidecarFolderDialog" => en ? "Allow access to the container folder and all recovery files to erase" : "Zugriff auf den Containerordner und alle zu löschenden Wiederherstellungsdateien erlauben",
            "sandboxFolderAccessRequired" => en ? "The folder permission is required for this operation and its sidecar files." : "Die Ordnerfreigabe ist für diese Aktion und ihre Begleitdateien erforderlich.",
            "sandboxParentUnavailable" => en ? "The required parent folder does not exist or cannot be resolved." : "Der benötigte übergeordnete Ordner existiert nicht oder kann nicht aufgelöst werden.",
            "sandboxWrongFolder" => en ? "Select exactly this folder: {0}" : "Bitte genau diesen Ordner auswählen: {0}",
            "sandboxLeaseFailed" => en ? "macOS did not grant a durable security-scoped file permission. The selection was rejected." : "macOS hat keine dauerhaft gehaltene Security-Scope-Dateifreigabe erteilt. Die Auswahl wurde verworfen.",
            "saveTestKeySheetDialog" => en ? "Save test key-sheet PDF (writes secrets to disk)" : "Test-Schlüsselzettel-PDF speichern (schreibt Geheimwerte auf Datenträger)",
            "inputsMissing" => en ? "Select at least one file or folder." : "Bitte mindestens eine Datei oder einen Ordner auswählen.",
            "targetMissing" => en ? "Choose a target archive." : "Bitte ein Zielarchiv auswählen.",
            "archiveTargetExists" => en ? "The archive target already exists. Choose a new numbered path." : "Das Archivziel existiert bereits. Bitte einen neuen nummerierten Pfad wählen.",
            "archiveTargetOverwritesInput" => en ? "The target archive would overwrite an input file." : "Das Zielarchiv würde eine Eingabedatei überschreiben.",
            "archiveTargetInsideInput" => en ? "The target archive must not be inside an input folder." : "Das Zielarchiv darf nicht innerhalb eines Eingabeordners liegen.",
            "passwordMismatch" => en ? "The user-password entries do not match." : "Die Userpasswort-Eingaben stimmen nicht überein.",
            "passwordLength" => en ? "The user password must contain 24 to 128 characters." : "Das Userpasswort muss 24 bis 128 Zeichen lang sein.",
            "entropyNotReady" => en
                ? "Insufficient mouse entropy. Required: {0}; current: {1}; missing: {2}. Move the pointer over the window."
                : "Nicht genug Maus-Entropie. Erforderlich: {0}; aktuell: {1}; fehlend: {2}. Bewege den Zeiger über dem Fenster.",
            "keySheetRequired" => en
                ? "Physically print the separate key sheets, or explicitly export a test PDF, for this exact archive path, suite and factor pair first."
                : "Zuerst die getrennten Schlüsselzettel für exakt diesen Archivpfad, dieses Verfahren und dieses Faktorenpaar physisch drucken oder ausdrücklich als Test-PDF exportieren.",
            "testPdfWarning" => en
                ? "This explicit test export permanently writes both secret factors to a PDF. Continue only in a controlled test environment."
                : "Dieser ausdrückliche Testexport schreibt beide geheimen Faktoren dauerhaft in eine PDF. Nur in einer kontrollierten Testumgebung fortfahren.",
            "noPhysicalPrinter" => en ? "No non-virtual CUPS printer is available." : "Es ist keine nicht virtuelle CUPS-Druckerwarteschlange verfügbar.",
            "creatingZpaq" => en ? "Creating ZPAQ stream …" : "ZPAQ-Stream wird erstellt …",
            "encryptingStreaming" => en ? "Encrypting the ZPAQ stream directly with {0} …" : "ZPAQ-Stream wird direkt mit {0} verschlüsselt …",
            "archiveCreated" => en ? "The archive and its KPAR2 recovery data were created." : "Archiv und KPAR2-Wiederherstellungsdaten wurden erstellt.",
            "zpaqCreateFailed" => en ? "ZPAQ could not create the archive." : "ZPAQ konnte das Archiv nicht erstellen.",
            "extractInputMissing" => en ? "Select an archive and output folder." : "Bitte Archiv und Zielordner auswählen.",
            "archiveMissing" => en ? "Select an existing archive." : "Bitte ein vorhandenes Archiv auswählen.",
            "extracting" => en ? "Extracting archive …" : "Archiv wird entpackt …",
            "extractingStreaming" => en ? "Authenticating and streaming the decrypted archive to ZPAQ …" : "Container wird authentifiziert und entschlüsselt direkt an ZPAQ gestreamt …",
            "archiveExtracted" => en ? "The archive was extracted." : "Das Archiv wurde entpackt.",
            "zpaqExtractFailed" => en ? "ZPAQ could not extract the archive." : "ZPAQ konnte das Archiv nicht entpacken.",
            "zpaqListFailed" => en ? "ZPAQ could not list the archive." : "ZPAQ konnte den Archivinhalt nicht anzeigen.",
            "extractedTo" => en ? "Extracted to" : "Entpackt nach",
            "emergencyRecoveryMissing" => en ? "No valid KPAR2-v3 recovery data was found." : "Es wurden keine gültigen KPAR2-v3-Wiederherstellungsdaten gefunden.",
            "emergencyEncryptedWarning" => en
                ? "Emergency mode skips KPAR2 metadata authentication, never changes the original and writes a new file. All factors and successful dual container authentication remain required. Continue?"
                : "Der Notfallmodus überspringt die KPAR2-Metadaten-Authentifizierung, verändert niemals das Original und schreibt eine neue Datei. Alle Faktoren und eine erfolgreiche doppelte Container-Authentifizierung bleiben erforderlich. Fortfahren?",
            "emergencyPlainWarning" => en
                ? "This plain recovery profile provides correction but no authenticity. Emergency mode never changes the original and writes a new file. Continue?"
                : "Dieses unverschlüsselte Profil bietet Fehlerkorrektur, aber keine Authentizität. Der Notfallmodus verändert niemals das Original und schreibt eine neue Datei. Fortfahren?",
            "encryptedHeaderWithoutRecovery" => en
                ? "The .kzpaq file has neither a valid encrypted header nor usable KPAR2 data and is blocked instead of being treated as plain ZPAQ."
                : "Die .kzpaq-Datei hat weder einen gültigen verschlüsselten Kopf noch nutzbare KPAR2-Daten und wird blockiert, statt als unverschlüsseltes ZPAQ behandelt zu werden.",
            "recoveryNewFile" => en ? "Recovery selected a new file: {0}" : "Wiederherstellung hat eine neue Datei ausgewählt: {0}",
            "retryAfterRecovery" => en ? "Container repaired; authentication and decryption are retried exactly once." : "Container repariert; Authentifizierung und Entschlüsselung werden genau einmal wiederholt.",
            "eraseMissing" => en ? "Select an existing encrypted container." : "Bitte einen vorhandenen verschlüsselten Container auswählen.",
            "eraseConfirmMissing" => en ? "Confirm the SSD/APFS limitation first." : "Bitte zuerst die SSD- und APFS-Grenze bestätigen.",
            "eraseFinalConfirm" => en
                ? "KPAR2 recovery data will be destroyed first, then this encrypted container will be corrupted and deleted. Continue?"
                : "Zuerst werden die KPAR2-Wiederherstellungsdaten vernichtet, danach wird dieser verschlüsselte Container beschädigt und gelöscht. Fortfahren?",
            "integrityActionBlocked" => en ? "This operation remains blocked until every app and native component passes all integrity and signature checks." : "Diese Aktion bleibt gesperrt, bis alle App- und Native-Komponenten sämtliche Integritäts- und Signaturprüfungen bestanden haben.",
            "integrityBlockedLog" => en ? "Integrity policy did not pass. Archive, extraction and erase operations remain disabled." : "Die Integritätsrichtlinie wurde nicht erfüllt. Archivierung, Entpacken und Löschen bleiben deaktiviert.",
            "generatedPasswordLog" => en ? "Generated factors A/B and prepared fresh salt/nonces in locked memory; source pools were consumed." : "Faktoren A/B erzeugt und frischen Salt/Nonces im gesperrten Speicher vorbereitet; Quellpools wurden verbraucht.",
            "keySheetTestPdfSavedLog" => en ? "Explicit test PDF containing both factors saved: {0}" : "Ausdrückliche Test-PDF mit beiden Faktoren gespeichert: {0}",
            "keySheetPrintedLog" => en ? "Three-page key-sheet job streamed to physical CUPS queue {0}; no app PDF was created." : "Dreiseitiger Schlüsselzettelauftrag an physische CUPS-Warteschlange {0} gestreamt; keine App-PDF wurde erzeugt.",
            "cipherSuiteSelected" => en ? "Cipher suite selected: {0}" : "Verschlüsselungsverfahren gewählt: {0}",
            "selectedSuiteMissing" => en ? "The signed, manifest-verified native reference library for {0} is unavailable." : "Die signierte und manifestgeprüfte native Referenzbibliothek für {0} ist nicht verfügbar.",
            "kalynaAvailable" => en ? "Kalyna reference library: available" : "Kalyna-Referenzbibliothek: verfügbar",
            "scannerAbsent" => en
                ? "QR-Scanner.app was not found; nothing to verify."
                : "QR-Scanner.app wurde nicht gefunden; nichts zu prüfen.",
            "scannerTrusted" => en
                ? "QR-Scanner.app verified against the pinned RSA-PSS/SHA-512 and ML-DSA-87 keys"
                : "QR-Scanner.app gegen die fest gebundenen RSA-PSS/SHA-512- und ML-DSA-87-Schlüssel geprüft",
            "scannerUntrusted" => en
                ? "WARNING: QR-Scanner.app failed its dual signature check — do not scan key sheets with it"
                : "WARNUNG: QR-Scanner.app hat die doppelte Signaturprüfung nicht bestanden — damit keine Schlüsselzettel scannen",
            "kalynaMissing" => en ? "Kalyna reference library: unavailable" : "Kalyna-Referenzbibliothek: nicht verfügbar",
            "threefishAvailable" => en ? "Threefish reference library: available" : "Threefish-Referenzbibliothek: verfügbar",
            "archiveCreatedOriginalsDeleted" => en
                ? "Archive created; the originals were deleted after a verified byte-for-byte comparison."
                : "Archiv erstellt; die Originale wurden nach geprüftem bitweisem Abgleich gelöscht.",
            "verifyingBeforeDelete" => en
                ? "Extracting the archive again and comparing it with the originals ..."
                : "Archiv wird erneut entpackt und mit den Originalen verglichen …",
            "verifyExtractFailed" => en
                ? "The archive could not be extracted for verification. No original was deleted."
                : "Das Archiv konnte zur Prüfung nicht entpackt werden. Es wurde keine Originaldatei gelöscht.",
            "verifyMismatch" => en
                ? "The archive does not reproduce the originals byte for byte. No original was deleted."
                : "Das Archiv gibt die Originale nicht bitgenau wieder. Es wurde keine Originaldatei gelöscht.",
            "verifyMatched" => en
                ? "Byte-for-byte comparison passed: {0} files, {1} bytes."
                : "Bitweiser Abgleich bestanden: {0} Dateien, {1} Bytes.",
            "deleteOriginalsFailed" => en
                ? "The comparison passed but an original could not be deleted."
                : "Der Abgleich war erfolgreich, aber eine Originaldatei konnte nicht gelöscht werden.",
            "originalsDeleted" => en
                ? "The originals were deleted; only the archive remains."
                : "Die Originale wurden gelöscht; es verbleibt nur das Archiv.",
            "verifyCleanupFailed" => en
                ? "The temporary verification copy could not be removed"
                : "Die temporäre Prüfkopie konnte nicht entfernt werden",
            "threefishMissing" => en ? "Threefish reference library: unavailable" : "Threefish-Referenzbibliothek: nicht verfügbar",
            "notFound" => en ? "not found" : "nicht gefunden",
            "dropAddedInputs" => en ? "Added {0} dropped item(s)." : "{0} abgelegte Elemente hinzugefügt.",
            "dropTargetArchive" => en ? "Target archive derived from drop: {0}" : "Zielarchiv aus Ablage abgeleitet: {0}",
            "dropExtractArchive" => en ? "Extraction archive set from drop: {0}" : "Entpack-Archiv per Ablage gesetzt: {0}",
            "dropOutputFolder" => en ? "Output folder set from drop: {0}" : "Zielordner per Ablage gesetzt: {0}",
            "dropEraseTarget" => en ? "Erase target set from drop: {0}" : "Löschziel per Ablage gesetzt: {0}",
            "finderOpenedArchive" => en ? "Archive opened from Finder: {0}" : "Archiv aus dem Finder geöffnet: {0}",
            "done" => en ? "Done" : "Fertig",
            _ => key,
        };
    }

    private string LoadLanguage()
    {
        string? value = _settingsStore.Read(LanguageSettingsFile)?.Trim();
        return value is "de" or "en" ? value : "de";
    }

    private EncryptionSuite LoadSuite()
    {
        string? value = _settingsStore.Read(CipherSuiteSettingsFile)?.Trim();
        return Enum.TryParse(value, ignoreCase: false, out EncryptionSuite suite) && Enum.IsDefined(suite)
            ? suite
            : EncryptionSuiteCatalog.Default;
    }

    private int LoadCompression()
    {
        string? value = _settingsStore.Read(CompressionSettingsFile)?.Trim();
        return int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int level)
            && level is >= 0 and <= MaxCompressionLevel
            ? level
            : DefaultCompressionLevel;
    }

    private void SelectLanguage(string language)
    {
        foreach (object? item in LanguageBox.Items)
        {
            if (item is ComboBoxItem { Tag: string tag } combo && tag == language)
            {
                LanguageBox.SelectedItem = combo;
                return;
            }
        }

        LanguageBox.SelectedIndex = 0;
    }

    /// <summary>
    /// Rebuilds the cipher picker in the current language.
    /// </summary>
    /// <remarks>
    /// Built from the catalogue rather than written into the window, so a suite
    /// cannot be offered that the catalogue does not know, and one it does know
    /// cannot be left out. The selection is preserved across the rebuild, which
    /// matters because this also runs when the user switches language.
    /// </remarks>
    private void PopulateSuites()
    {
        EncryptionSuite selected = CipherSuiteBox.SelectedItem is ComboBoxItem { Tag: string tag }
            && Enum.TryParse(tag, ignoreCase: false, out EncryptionSuite current)
            ? current
            : EncryptionSuiteCatalog.Default;

        CipherSuiteBox.Items.Clear();
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            CipherSuiteBox.Items.Add(new ComboBoxItem
            {
                Content = EncryptionSuiteCatalog.DisplayName(suite, IsEnglish),
                Tag = suite.ToString(),
            });
        }

        SelectSuite(selected);
    }

    private void SelectSuite(EncryptionSuite suite)
    {
        string expected = suite.ToString();
        foreach (object? item in CipherSuiteBox.Items)
        {
            if (item is ComboBoxItem { Tag: string tag } combo && tag == expected)
            {
                CipherSuiteBox.SelectedItem = combo;
                return;
            }
        }

        CipherSuiteBox.SelectedIndex = 0;
    }
}
