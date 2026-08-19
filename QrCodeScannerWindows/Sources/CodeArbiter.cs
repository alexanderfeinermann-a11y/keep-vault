namespace QrScanner;

// Decides which decoded QR code may be shown to the user.
//
// A QR code carries Reed-Solomon parity, so a decoder does not return a
// damaged payload: it either repairs the damage and returns the original
// content, or it fails and returns nothing at all. "Error-free" is therefore
// not a property this app can measure after the fact - it is the reason a
// payload arrived here in the first place. A code that is creased, stained or
// half out of frame simply never appears among the detections.
//
// That is what makes a sheet with two identical codes worth reading: the
// damaged one drops out on its own, and whichever one still decodes carries
// the original content. This type turns that into an explicit decision instead
// of leaving it to whichever detection happened to arrive first.
//
// Deliberately the same rule, the same constants and the same vocabulary as the
// macOS scanner's CodeArbiter.swift. A key sheet printed on one platform is
// read on whichever one is to hand years later, and the two must not disagree
// about when a factor has been confirmed.

/// <summary>
/// One QR code decoded from a single camera frame.
/// </summary>
/// <param name="Payload">What the code decoded to.</param>
/// <param name="CenterX">Horizontal centre, 0 to 1 across the frame.</param>
/// <param name="CenterY">Vertical centre, 0 to 1 down the frame.</param>
/// <remarks>
/// The centre is in the normalised coordinate space the capture layer reports.
/// It is what separates two physical codes on a sheet from one code reported
/// twice, which is the difference between a payload that was confirmed by a
/// second printed copy and one that was not.
/// </remarks>
public readonly record struct Detection(string Payload, double CenterX, double CenterY);

/// <summary>
/// Why a payload was accepted.
/// </summary>
/// <remarks>
/// The distinction reaches the user, because the two cases carry genuinely
/// different weight: one is two printed codes agreeing with each other, the
/// other is a single code that no second copy could confirm.
/// </remarks>
public enum CorroborationKind
{
    /// <summary>Two or more codes in the same frame decoded to the same content.</summary>
    MatchingCodes,

    /// <summary>Only one code was readable; it repeated itself instead.</summary>
    RepeatedReads,
}

public readonly record struct Corroboration(CorroborationKind Kind, int Count);

public enum ScanOutcomeKind
{
    /// <summary>Nothing readable in view.</summary>
    Searching,

    /// <summary>One code is readable and has agreed with itself this often so far.</summary>
    Confirming,

    /// <summary>
    /// Codes in view decoded to different content. Nothing is accepted: on a
    /// sheet whose codes are meant to be identical this means something is
    /// wrong, and anywhere else it means the camera is looking at more than one
    /// code and cannot know which is meant.
    /// </summary>
    Conflict,

    /// <summary>A payload survived arbitration and may be shown.</summary>
    Accepted,
}

public sealed record ScanOutcome(
    ScanOutcomeKind Kind,
    string? Payload = null,
    Corroboration Corroboration = default,
    int Progress = 0,
    int Required = 0,
    IReadOnlyList<string>? ConflictingPayloads = null)
{
    internal static ScanOutcome Searching { get; } = new(ScanOutcomeKind.Searching);

    internal static ScanOutcome Confirming(int progress, int required) =>
        new(ScanOutcomeKind.Confirming, Progress: progress, Required: required);

    internal static ScanOutcome Conflict(IReadOnlyList<string> payloads) =>
        new(ScanOutcomeKind.Conflict, ConflictingPayloads: payloads);

    internal static ScanOutcome Accepted(string payload, CorroborationKind kind, int count) =>
        new(ScanOutcomeKind.Accepted, payload, new Corroboration(kind, count));
}

public sealed class CodeArbiter
{
    /// <summary>
    /// How often a lone code must repeat itself before it is accepted.
    /// </summary>
    /// <remarks>
    /// Two printed codes confirm each other in a single frame and are accepted
    /// at once. A single readable code has nothing to be checked against, so it
    /// is required to return the same content on this many frames in a row
    /// instead - roughly a quarter second of video. A decoder that misreads
    /// does not misread identically frame after frame while the sheet, the hand
    /// holding it and the lighting all move.
    /// </remarks>
    public int RequiredRepeats { get; }

    /// <summary>
    /// How many consecutive frames without any readable code are tolerated
    /// before the tally is dropped.
    /// </summary>
    /// <remarks>
    /// Detection flickers between frames, and resetting on the first empty one
    /// would make a lone code never reach the repeat count.
    /// </remarks>
    public int ToleratedMisses { get; }

    /// <summary>
    /// How far apart two detections must be, as a fraction of the frame, to
    /// count as two separate printed codes rather than one reported twice.
    /// </summary>
    public double MinimumSeparation { get; }

    private string? _candidate;
    private int _confirmations;
    private int _misses;

    public CodeArbiter(int requiredRepeats = 8, int toleratedMisses = 15, double minimumSeparation = 0.02)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(requiredRepeats, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(toleratedMisses);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(minimumSeparation);
        RequiredRepeats = requiredRepeats;
        ToleratedMisses = toleratedMisses;
        MinimumSeparation = minimumSeparation;
    }

    /// <summary>
    /// Feeds one frame's detections in and reports what may be done with them.
    /// </summary>
    public ScanOutcome Admit(IReadOnlyList<Detection> detections)
    {
        ArgumentNullException.ThrowIfNull(detections);
        if (detections.Count == 0)
        {
            _misses++;
            if (_misses > ToleratedMisses)
            {
                Reset();
            }

            return _candidate is null
                ? ScanOutcome.Searching
                : ScanOutcome.Confirming(_confirmations, RequiredRepeats);
        }

        _misses = 0;

        var distinct = new SortedSet<string>(StringComparer.Ordinal);
        foreach (Detection detection in detections)
        {
            distinct.Add(detection.Payload);
        }

        if (distinct.Count != 1)
        {
            // Two codes that disagree cannot both be the sheet's content, and
            // picking either one would be a guess. The user is told instead,
            // because only they can see what is actually in front of the lens.
            Reset();
            return ScanOutcome.Conflict([.. distinct]);
        }

        string payload = distinct.Min!;
        int copies = SeparateCopies(detections);
        if (copies >= 2)
        {
            // Two printed codes carrying the same content. Each one already
            // passed its own error correction, and they agree with each other,
            // which is as much confirmation as a sheet can offer.
            Reset();
            return ScanOutcome.Accepted(payload, CorroborationKind.MatchingCodes, copies);
        }

        if (string.Equals(_candidate, payload, StringComparison.Ordinal))
        {
            _confirmations++;
        }
        else
        {
            _candidate = payload;
            _confirmations = 1;
        }

        if (_confirmations < RequiredRepeats)
        {
            return ScanOutcome.Confirming(_confirmations, RequiredRepeats);
        }

        int reads = _confirmations;
        Reset();
        return ScanOutcome.Accepted(payload, CorroborationKind.RepeatedReads, reads);
    }

    /// <summary>
    /// Counts how many physically separate codes these detections represent.
    /// </summary>
    /// <remarks>
    /// Detections are grouped by position, so a code the capture layer reports
    /// twice in one frame cannot masquerade as a second printed copy. Without
    /// this the strongest acceptance the app offers would rest on a duplicate
    /// report rather than on a second code actually being there.
    /// </remarks>
    private int SeparateCopies(IReadOnlyList<Detection> detections)
    {
        var centers = new List<(double X, double Y)>();
        foreach (Detection detection in detections)
        {
            bool isNew = true;
            foreach ((double x, double y) in centers)
            {
                if (double.Hypot(x - detection.CenterX, y - detection.CenterY) <= MinimumSeparation)
                {
                    isNew = false;
                    break;
                }
            }

            if (isNew)
            {
                centers.Add((detection.CenterX, detection.CenterY));
            }
        }

        return centers.Count;
    }

    public void Reset()
    {
        _candidate = null;
        _confirmations = 0;
        _misses = 0;
    }
}
