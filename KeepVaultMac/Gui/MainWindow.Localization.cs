using Avalonia.Controls;
using KalynaArchiver.Services;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private void ApplyLanguage()
    {
        Title = "Keep Vault";
        TitleText.Text = "Keep Vault";
        SubtitleText.Text = T("subtitle");
        LanguageLabel.Text = T("language");
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
        CreateArchiveButton.Content = T("saveArchive");
        CreatePasswordSetupTitle.Text = T("createPasswordTitle");
        CreatePasswordSetupHelpText.Text = T("createPasswordHelp");
        CreatePasswordLabel.Text = T("userPassword");
        CreatePasswordConfirmLabel.Text = T("repeatPassword");
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
        bool en = _language == "en";
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
                ? "Drop a folder to create archive(1).kzpaq there, or a file to derive name(1).kzpaq."
                : "Ordner ablegen, um dort archive(1).kzpaq zu erzeugen, oder eine Datei für name(1).kzpaq ablegen.",
            "browse" => en ? "Browse" : "Auswählen",
            "compression" => en ? "Compression" : "Kompression",
            "encrypt" => en ? "Encrypt archive" : "Archiv verschlüsseln",
            "cipherSuite" => en ? "Cipher suite" : "Verfahren",
            "argon2Profile" => en
                ? "Argon2id: 1 GiB memory, 4 iterations, parallelism 4, locked RAM required"
                : "Argon2id: 1 GiB Speicher, 4 Iterationen, Parallelität 4, gesperrter RAM erforderlich",
            "saveArchive" => en ? "Save archive" : "Archiv speichern",
            "createPasswordTitle" => en ? "Three-part password" : "Dreiteiliges Passwort",
            "createPasswordHelp" => en
                ? "Extraction requires the user password plus independently generated factors A and B."
                : "Zum Entpacken werden Userpasswort sowie die unabhängig generierten Faktoren A und B benötigt.",
            "userPassword" => en ? "User password" : "Userpasswort",
            "repeatPassword" => en ? "Repeat user password" : "Userpasswort wiederholen",
            "passwordHelp" => en
                ? "24 to 128 characters, at least 3 character groups, 12 distinct and 12 non-hex characters, no hex run of 8+, and at least 128 conservative entropy bits."
                : "24 bis 128 Zeichen, mindestens 3 Zeichengruppen, 12 verschiedene und 12 Nicht-Hex-Zeichen, keine Hex-Folge ab 8 Zeichen und mindestens 128 Bit konservative Bewertung.",
            "generatorTitle" => en ? "Two independent 512-bit factors" : "Zwei unabhängige 512-Bit-Faktoren",
            "generatorHelp" => en
                ? "Five separate entropy pools need at least 512 mouse samples each. Generation atomically creates factors A/B, salt and both nonce parts, then consumes all source pools."
                : "Fünf getrennte Entropiepools benötigen je mindestens 512 Maus-Samples. Generieren erzeugt Faktoren A/B, Salt und beide Nonce-Teile atomar und verbraucht danach alle Quellpools.",
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
            "entropyCollecting" => en
                ? "Collecting: total {0}; A {1}/{6}; B {2}/{6}; salt {3}/{6}; nonce 1 {4}/{6}; nonce 2 {5}/{6}"
                : "Sammlung: gesamt {0}; A {1}/{6}; B {2}/{6}; Salt {3}/{6}; Nonce 1 {4}/{6}; Nonce 2 {5}/{6}",
            "entropyPrepared" => en
                ? "Ready and source pools consumed. Fresh pools: total {0}; A {1}/{6}; B {2}/{6}; salt {3}/{6}; nonce 1 {4}/{6}; nonce 2 {5}/{6}"
                : "Bereit und Quellpools verbraucht. Frische Pools: gesamt {0}; A {1}/{6}; B {2}/{6}; Salt {3}/{6}; Nonce 1 {4}/{6}; Nonce 2 {5}/{6}",
            "entropyRetry" => en
                ? "Factors remain valid; a retry needs fresh salt/nonces: total {0}; A {1}/{6}; B {2}/{6}; salt {3}/{6}; nonce 1 {4}/{6}; nonce 2 {5}/{6}"
                : "Faktoren bleiben gültig; ein Wiederholungsversuch benötigt frischen Salt/Nonces: gesamt {0}; A {1}/{6}; B {2}/{6}; Salt {3}/{6}; Nonce 1 {4}/{6}; Nonce 2 {5}/{6}",
            "passwordEntropy" => en ? "Conservative entropy: {0:0.0} / {1:0} bits" : "Konservative Entropie: {0:0.0} / {1:0} Bit",
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
            "passwordLowEntropy" => en ? "Increase the conservative score to 128 bits." : "Konservative Bewertung auf 128 Bit erhöhen.",
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
                ? "Enter the user password and both factors from the separately stored key sheets."
                : "Userpasswort und beide Faktoren von den getrennt gelagerten Schlüsselzetteln eingeben.",
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
                ? "Per-file hardware erase cannot be guaranteed on SSDs or APFS."
                : "Per-Datei-Hardwarelöschung kann auf SSDs und APFS nicht garantiert werden.",
            "eraseConfirm" => en
                ? "I understand the SSD/APFS boundary and want to delete this encrypted container."
                : "Ich verstehe die SSD- und APFS-Grenze und möchte diesen verschlüsselten Container löschen.",
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
            "emergencyRecoveryMissing" => en ? "No valid KPAR2-v2 recovery data was found." : "Es wurden keine gültigen KPAR2-v2-Wiederherstellungsdaten gefunden.",
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
            "kalynaMissing" => en ? "Kalyna reference library: unavailable" : "Kalyna-Referenzbibliothek: nicht verfügbar",
            "threefishAvailable" => en ? "Threefish reference library: available" : "Threefish-Referenzbibliothek: verfügbar",
            "scanFactorATitle" => en ? "Scan factor A" : "Faktor A scannen",
            "scanFactorBTitle" => en ? "Scan factor B" : "Faktor B scannen",
            "scanSucceeded" => en
                ? "A key-sheet factor was read from the camera."
                : "Ein Schlüsselzettel-Faktor wurde per Kamera eingelesen.",
            "scanFailed" => en
                ? "The QR code could not be read."
                : "Der QR-Code konnte nicht gelesen werden.",
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
            : EncryptionSuite.Threefish1024;
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
