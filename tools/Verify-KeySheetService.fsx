#r "../KeepVaultMac/bin/Release/net10.0/osx-arm64/Keep Vault.dll"
#r "../KeepVaultMac/bin/Release/net10.0/osx-arm64/PdfSharp.dll"

open System
open System.Diagnostics
open System.IO
open KalynaArchiver.Services
open PdfSharp.Pdf.IO

let require condition message =
    if not condition then invalidOp message

let extractPageText pdfPath pageNumber =
    let tool =
        [ "/opt/homebrew/bin/pdftotext"; "/usr/local/bin/pdftotext" ]
        |> List.tryFind File.Exists
        |> Option.defaultWith (fun () -> invalidOp "pdftotext fehlt; die Faktortrennung kann nicht unabhängig geprüft werden.")
    let startInfo = ProcessStartInfo(tool, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true)
    for argument in [ "-f"; string pageNumber; "-l"; string pageNumber; pdfPath; "-" ] do
        startInfo.ArgumentList.Add(argument)
    use child = Process.Start(startInfo)
    let output = child.StandardOutput.ReadToEnd()
    let error = child.StandardError.ReadToEnd()
    child.WaitForExit()
    require (child.ExitCode = 0) $"pdftotext schlug fehl: {error}"
    output

let factorA = String.replicate 128 "A"
let factorB = String.replicate 128 "B"
let temporary =
    Path.Combine(__SOURCE_DIRECTORY__, $".keep-vault-keysheet-check-{Guid.NewGuid():N}")
    |> Directory.CreateDirectory
let archivePath = Path.Combine(temporary.FullName, "prüfung.kzpaq")
let pdfPath = Path.Combine(temporary.FullName, "test-schluesselzettel.pdf")
let data = KeySheetData(archivePath, EncryptionSuite.Threefish1024, factorA, factorB, DateTime(2026, 8, 15, 12, 34, 56))

try
    printfn "CHECK fingerprint"
    let fingerprint1 = KeySheetService.BuildBindingFingerprint(data)
    let fingerprint2 = KeySheetService.BuildBindingFingerprint(data)
    require (fingerprint1 = fingerprint2) "Der Bindungsfingerprint ist nicht deterministisch."
    require (fingerprint1.Length = 128 + 1 + 256) "Der duale Bindungsfingerprint hat eine falsche Länge."
    let swapped = KeySheetData(archivePath, EncryptionSuite.Threefish1024, factorB, factorA, data.CreatedAt)
    let otherSuite = KeySheetData(archivePath, EncryptionSuite.Kalyna512_512, factorA, factorB, data.CreatedAt)
    let otherPath = KeySheetData(Path.Combine(temporary.FullName, "anderes.kzpaq"), EncryptionSuite.Threefish1024, factorA, factorB, data.CreatedAt)
    require (fingerprint1 <> KeySheetService.BuildBindingFingerprint(swapped)) "Der Fingerprint bindet die Reihenfolge A/B nicht."
    require (fingerprint1 <> KeySheetService.BuildBindingFingerprint(otherSuite)) "Der Fingerprint bindet die Suite nicht."
    require (fingerprint1 <> KeySheetService.BuildBindingFingerprint(otherPath)) "Der Fingerprint bindet den kanonischen Zielpfad nicht."

    let service = KeySheetService()
    printfn "CHECK test PDF"
    service.SaveTestPdf(data, pdfPath)
    printfn "CHECK PDF structure"
    require (File.Exists(pdfPath)) "Der explizite Test-PDF-Export fehlt."
    let mode = File.GetUnixFileMode(pdfPath)
    printfn "CHECK PDF MODE %A" mode
    require (mode = (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)) "Die Test-PDF wurde nicht mit exklusiven 0600-Rechten angelegt."
    let mutable overwriteRefused = false
    try
        service.SaveTestPdf(data, pdfPath)
    with
    | :? ComponentModel.Win32Exception -> overwriteRefused <- true
    require overwriteRefused "Der Test-PDF-Export hat eine vorhandene Datei überschrieben."
    use document = PdfReader.Open(pdfPath, PdfDocumentOpenMode.Import)
    require (document.PageCount = 3) "Der Test-PDF-Export enthält nicht genau drei Seiten."
    require (not (document.Pages[1].Elements.ContainsKey("/Contents"))) "Die Trennseite enthält entgegen der Vorgabe einen Content-Stream."
    let pageAText = extractPageText pdfPath 1 |> String.filter (Char.IsWhiteSpace >> not)
    let blankText = extractPageText pdfPath 2
    let pageBText = extractPageText pdfPath 3 |> String.filter (Char.IsWhiteSpace >> not)
    require (pageAText.Contains(factorA) && not (pageAText.Contains(factorB))) "Seite A enthält nicht ausschließlich Faktor A."
    require (String.IsNullOrWhiteSpace(blankText)) "Die Trennseite ist nicht textlich leer."
    require (pageBText.Contains(factorB) && not (pageBText.Contains(factorA))) "Seite B enthält nicht ausschließlich Faktor B."

    printfn "CHECK physical printers"
    let printers =
        service.GetVerifiedPhysicalPrintersAsync()
        |> Async.AwaitTask
        |> Async.RunSynchronously
    require (printers.Count > 0) "Auf diesem Mac wurde kein verifizierbares physisches Druckziel gefunden."
    for printer in printers do
        require printer.IsVerifiedPhysical $"Ein nicht verifiziertes Druckziel wurde ausgegeben: {printer.Name}"
        printfn "VERIFIED PRINTER %s | %A | %s" printer.Name printer.Evidence printer.VerificationMessage

    let mutable virtualRefused = false
    try
        KeySheetService.EnsurePhysicalPrinter("Microsoft Print to PDF")
    with
    | :? ArgumentException -> virtualRefused <- true
    | :? InvalidOperationException -> virtualRefused <- true
    require virtualRefused "Ein virtuelles PDF-Druckziel wurde nicht gesperrt."

    printfn "PASS Bindungsfingerprint, dreiseitige PDF-Struktur und physische Druckerfilterung"
finally
    if File.Exists(pdfPath) then
        File.Delete(pdfPath)
    temporary.Delete(true)
