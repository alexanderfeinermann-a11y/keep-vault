using QRCoder;

namespace QrScanner.Tests;

/// <summary>
/// Draws QR codes into a frame buffer shaped like the camera's.
/// </summary>
/// <remarks>
/// The codes are produced by QRCoder rather than by the library that decodes
/// them. Encoding and decoding with the same implementation would test that it
/// agrees with itself; a printed key sheet is made by one implementation and
/// read by another, and that is what this reproduces.
///
/// The buffer is BGRA in the camera's own layout, so the test enters the
/// decoder through exactly the call the frame handler makes.
/// </remarks>
internal static class QrImage
{
    internal static byte[] RenderPair(
        string leftPayload,
        string rightPayload,
        int codeSize,
        int gap,
        int width,
        int height,
        bool destroyLeft = false)
    {
        byte[] frame = new byte[width * height * 4];

        // White page. A camera frame is not transparent, and the decoder needs
        // the quiet zone around each code to find it at all.
        for (int index = 0; index < frame.Length; index++)
        {
            frame[index] = 0xFF;
        }

        DrawCode(frame, width, height, leftPayload, gap, gap, codeSize, destroyLeft);
        DrawCode(frame, width, height, rightPayload, (2 * gap) + codeSize, gap, codeSize, destroy: false);
        return frame;
    }

    private static void DrawCode(
        byte[] frame,
        int width,
        int height,
        string payload,
        int originX,
        int originY,
        int size,
        bool destroy)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        int modules = data.ModuleMatrix.Count;
        double moduleSize = (double)size / modules;

        for (int row = 0; row < modules; row++)
        {
            for (int column = 0; column < modules; column++)
            {
                if (!data.ModuleMatrix[row][column])
                {
                    continue;
                }

                int startX = originX + (int)(column * moduleSize);
                int startY = originY + (int)(row * moduleSize);
                int endX = originX + (int)((column + 1) * moduleSize);
                int endY = originY + (int)((row + 1) * moduleSize);
                FillRectangle(frame, width, height, startX, startY, endX, endY, 0x00);
            }
        }

        if (destroy)
        {
            // Not "damaged": a QR code carries Reed-Solomon parity, so light
            // damage is repaired and returns the original. Painting the code
            // out is what actually removes it from the frame, which is the case
            // the arbiter's fallback exists for.
            FillRectangle(frame, width, height, originX, originY, originX + size, originY + size, 0xC0);
        }
    }

    private static void FillRectangle(
        byte[] frame,
        int width,
        int height,
        int startX,
        int startY,
        int endX,
        int endY,
        byte level)
    {
        for (int y = Math.Max(0, startY); y < Math.Min(height, endY); y++)
        {
            for (int x = Math.Max(0, startX); x < Math.Min(width, endX); x++)
            {
                int offset = ((y * width) + x) * 4;
                frame[offset] = level;
                frame[offset + 1] = level;
                frame[offset + 2] = level;
                frame[offset + 3] = 0xFF;
            }
        }
    }
}
