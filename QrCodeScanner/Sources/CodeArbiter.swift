import CoreGraphics
import Foundation

// Decides which decoded QR code may be shown to the user.
//
// A QR code carries Reed-Solomon parity, so a decoder does not return a
// damaged payload: it either repairs the damage and returns the original
// content, or it fails and returns nothing at all. "Fehlerfrei" is therefore
// not a property this app can measure after the fact — it is the reason a
// payload arrived here in the first place. A code that is creased, stained or
// half out of frame simply never appears among the detections.
//
// That is what makes a sheet with two identical codes worth reading: the
// damaged one drops out on its own, and whichever one still decodes carries
// the original content. This type turns that into an explicit decision instead
// of leaving it to whichever detection happened to arrive first.

/// One QR code decoded from a single camera frame.
///
/// The centre is in the normalised coordinate space the capture layer reports
/// (0…1 across the frame). It is what separates two physical codes on a sheet
/// from one code reported twice, which is the difference between a payload
/// that was confirmed by a second printed copy and one that was not.
struct Detection: Equatable {
    let payload: String
    let center: CGPoint

    init(payload: String, center: CGPoint) {
        self.payload = payload
        self.center = center
    }
}

/// Why a payload was accepted.
///
/// The distinction reaches the user, because the two cases carry genuinely
/// different weight: one is two printed codes agreeing with each other, the
/// other is a single code that no second copy could confirm.
enum Corroboration: Equatable {
    /// Two or more codes in the same frame decoded to the same content. On a
    /// key sheet this is both printed codes agreeing.
    case matchingCodes(count: Int)

    /// Only one code was readable. It returned identical content on this many
    /// consecutive frames before it was accepted.
    case repeatedReads(count: Int)
}

enum ScanOutcome: Equatable {
    /// Nothing readable in view.
    case searching

    /// One code is readable and has agreed with itself this often so far.
    case confirming(progress: Int, required: Int)

    /// Codes in view decoded to different content. Nothing is accepted: on a
    /// sheet whose codes are meant to be identical this means something is
    /// wrong, and anywhere else it means the camera is looking at more than one
    /// code and cannot know which is meant.
    case conflict(payloads: [String])

    /// A payload survived arbitration and may be shown.
    case accepted(payload: String, corroboration: Corroboration)
}

struct CodeArbiter {
    /// How often a lone code must repeat itself before it is accepted.
    ///
    /// Two printed codes confirm each other in a single frame and are accepted
    /// at once. A single readable code has nothing to be checked against, so it
    /// is required to return the same content on this many frames in a row
    /// instead — roughly a quarter second of video. A decoder that misreads
    /// does not misread identically frame after frame while the sheet, the
    /// hand holding it and the lighting all move.
    let requiredRepeats: Int

    /// How many consecutive frames without any readable code are tolerated
    /// before the tally is dropped. Detection flickers between frames, and
    /// resetting on the first empty one would make a lone code never reach the
    /// repeat count.
    let toleratedMisses: Int

    /// How far apart two detections must be, as a fraction of the frame, to
    /// count as two separate printed codes rather than one reported twice.
    let minimumSeparation: CGFloat

    private var candidate: String?
    private var confirmations = 0
    private var misses = 0

    init(requiredRepeats: Int = 8, toleratedMisses: Int = 15, minimumSeparation: CGFloat = 0.02) {
        self.requiredRepeats = requiredRepeats
        self.toleratedMisses = toleratedMisses
        self.minimumSeparation = minimumSeparation
    }

    /// Feeds one frame's detections in and reports what may be done with them.
    mutating func admit(_ detections: [Detection]) -> ScanOutcome {
        guard !detections.isEmpty else {
            misses += 1
            if misses > toleratedMisses {
                reset()
            }
            return candidate == nil
                ? .searching
                : .confirming(progress: confirmations, required: requiredRepeats)
        }

        misses = 0

        let distinct = Set(detections.map(\.payload))
        guard distinct.count == 1, let payload = distinct.first else {
            // Two codes that disagree cannot both be the sheet's content, and
            // picking either one would be a guess. The user is told instead,
            // because only they can see what is actually in front of the lens.
            reset()
            return .conflict(payloads: distinct.sorted())
        }

        let copies = separateCopies(among: detections)
        if copies >= 2 {
            // Two printed codes carrying the same content. Each one already
            // passed its own error correction, and they agree with each other,
            // which is as much confirmation as a sheet can offer.
            reset()
            return .accepted(payload: payload, corroboration: .matchingCodes(count: copies))
        }

        if candidate == payload {
            confirmations += 1
        } else {
            candidate = payload
            confirmations = 1
        }

        guard confirmations >= requiredRepeats else {
            return .confirming(progress: confirmations, required: requiredRepeats)
        }

        let reads = confirmations
        reset()
        return .accepted(payload: payload, corroboration: .repeatedReads(count: reads))
    }

    /// Counts how many physically separate codes these detections represent.
    ///
    /// Detections are grouped by position, so a code the capture layer reports
    /// twice in one frame cannot masquerade as a second printed copy. Without
    /// this the strongest acceptance the app offers would rest on a duplicate
    /// report rather than on a second code actually being there.
    private func separateCopies(among detections: [Detection]) -> Int {
        var centers: [CGPoint] = []
        for detection in detections {
            let isNew = centers.allSatisfy { existing in
                hypot(existing.x - detection.center.x, existing.y - detection.center.y) > minimumSeparation
            }
            if isNew {
                centers.append(detection.center)
            }
        }
        return centers.count
    }

    mutating func reset() {
        candidate = nil
        confirmations = 0
        misses = 0
    }
}
