# QR-Scanner (Windows)

Standalone Windows app that reads a QR code through the camera, shows the
content in a text box and puts it on the clipboard on request. The content is
**not** written to a file.

It is independent of Keep Vault: own folder, own project, own dependency set,
own build, own signature. It shares no source with Keep Vault, reads nothing out
of its installation, and Keep Vault's build scripts do not touch it. The reason
is not tidiness — the scanner needs a camera, and the program that holds archive
keys must never be the one that has one.

The macOS counterpart is [`../QrCodeScanner`](../QrCodeScanner). Both make the
same decision about which of the two printed codes is taken, in the same words,
because a key sheet printed on one platform is read on whichever one is to hand
years later.

## Building and installing

```powershell
pwsh QrCodeScannerWindows\tools\Build-QrScanner-Windows.ps1
```

The script runs the tests first, generates the icon, publishes a self-contained
`QR-Scanner.exe` to `QrCodeScannerWindows\dist\`, and refuses to finish if any
Keep Vault native component turned up in that output. Add `-Sign` on the release
machine to attach the detached RSA-PSS/SHA-512 and ML-DSA-87 signature.

Copy `QR-Scanner.exe` and its `.khsig` beside `Keep Vault.exe`, or into a
`QR-Scanner` folder next to it. Keep Vault looks in both places at startup and
writes the result into its security log. It never loads the scanner's code; it
only vouches for it.

On first use Windows asks for the camera. If the answer is no, the app says so
and points at Settings › Privacy & security › Camera, because a desktop app gets
no second chance to ask.

## Which of the two QR codes applies

A key sheet carries the same factor in two QR codes. That is the reason for the
rule, and it is written out in full in
[`Sources/CodeArbiter.cs`](Sources/CodeArbiter.cs):

| What the camera sees | What the app does |
| --- | --- |
| Both codes readable, same content | Taken at once — "confirmed by 2 codes" |
| One code damaged, one readable | The readable one applies, after 8 identical reads in a row |
| Both codes readable, **different** content | Nothing is taken; the contradiction is reported |
| Nothing readable | Keep looking |

The decisive point: "error-free" is not something measured afterwards. A QR code
carries Reed-Solomon parity, so a decoder does not return damaged content — it
repairs the damage and returns the original, or it fails and returns nothing. A
creased, smeared or clipped code therefore never appears among the detections at
all. The readable code is left over by itself.

That two decoded codes carry the same content is checked, not assumed. If they
contradict each other, any choice would be a guess — and what would be guessed
at is half of an archive key. The app says so instead.

Two reports of a single code in one frame do not count as two codes: detections
are grouped by position, or the app's strongest confirmation would rest on a
duplicate report.

### Checked against real codes

`QrScanner.Tests` renders two QR codes into a frame buffer shaped exactly like
the camera's, hands it to the same `Decode` call the frame handler uses, and
checks that two separate detections come back and that the arbiter accepts them
as confirmed by two codes. The codes are produced by QRCoder and read by ZXing —
two different implementations, which is what a printed sheet actually involves.
Painting one code out leaves exactly one detection carrying the whole factor.

```powershell
dotnet run --project QrCodeScannerWindows\QrScanner.Tests.csproj
```

## What the app does not write to disk

- **No file dialogs, no recent-files list, no settings file.** The app has
  nothing to read and nothing to write.
- **Spell checking is off** on the text box. The checker learns words into the
  user's dictionary.
- **Undo history is off.** It is another copy of everything the box ever held.
- **Nothing is logged.** The content appears in no log line, no exception
  message and no window title.
- **Ctrl+C in the text box** is intercepted and routed through the same copy
  path as the button, so what leaves is the payload rather than the escaped
  rendering shown on screen — and so the same expiry applies to it.

## What this app cannot prevent

For the list above to be worth anything, here is the honest other half.

- **The clipboard.** The copy button is the one place the value leaves the app.
  The clipboard belongs to Windows, not to this app. What can be done is done:
  the entry carries `CanIncludeInClipboardHistory=0` and
  `CanUploadToCloudClipboard=0`, which keep it out of the Win+V history and off
  the user's other devices, plus
  `ExcludeClipboardContentFromMonitorProcessing` for third-party clipboard
  managers; it is placed without the "leave on clipboard after exit" flag; and
  it is cleared again after **90 seconds**. It is only cleared if the clipboard
  still holds the same value — if the user has since copied something else,
  that is left alone.
- **Paging and crash dumps.** The value lives in memory. What Windows writes to
  the page file or into a crash dump is not this app's decision.
- **The camera sees the sheet.** A printed sheet in front of a lens is visible —
  to the camera and to everything else in the room.
- **The decoder is a third-party library.** Windows exposes no barcode decoder a
  desktop app may call: the WinRT barcode API wants a point-of-sale scanner
  device, and the OCR engine does not read QR. The macOS scanner uses the
  system's own decoder; this one uses ZXing, pinned by version and hash like
  every other dependency in this repository.

## Layout

| File | Content |
| --- | --- |
| `Sources/CodeArbiter.cs` | The rule for which of the two codes applies. No UI types, so it stays testable. |
| `Sources/PayloadInspector.cs` | Length limit and notices about invisible characters in the content. |
| `Sources/ScanSession.cs` | Camera and decoding. |
| `Sources/VolatileClipboard.cs` | "Copy" with an expiry. |
| `Sources/MainWindow.cs` | The window; contains the settings against writing to disk. |
| `Sources/Localization.cs` | Every visible string, in both languages. |
| `Sources/Program.cs` | Start-up. |
| `Tests/ArbiterTests.cs` | 109 checks of the rule, the inspector, both languages and a real decode. |
| `Tests/QrImage.cs` | Renders codes into a camera-shaped frame for that decode. |
| `tools/Build-QrScanner-Windows.ps1` | Test, build, sign. |
| `tools/New-QrScannerIcon.ps1` | Generates the icon, which is itself a scannable QR code. |
