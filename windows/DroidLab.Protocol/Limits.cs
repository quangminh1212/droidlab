namespace DroidLab.Protocol;

/// <summary>
/// Applies the DLWP/1 limits rules (RFC-0001 section 7.3).
/// </summary>
/// <remarks>
/// The rules differ by resource and the difference is deliberate: a video
/// geometry request is <b>clamped</b> rather than refused, because a controller
/// asking for more pixels than the device can encode still gets a usable stream;
/// while a file chunk larger than the maximum is <b>refused</b>, because
/// accepting it would mean allocating a buffer the limit exists to bound.
/// Clamping where the protocol refuses, or vice versa, is a real defect in both
/// directions.
/// </remarks>
public static class Limits
{
    /// <summary>The video geometry that will actually be used.</summary>
    /// <param name="Width">The effective width in pixels. Always even.</param>
    /// <param name="Height">The effective height in pixels. Always even.</param>
    /// <param name="Fps">The effective frame rate.</param>
    /// <param name="ClampedBy">Which limit decided the result, for the UI to explain it.</param>
    public readonly record struct VideoGeometry(int Width, int Height, int Fps, string ClampedBy);

    /// <summary>
    /// Clamps a requested video geometry to the agent's limits and the screen size.
    /// </summary>
    /// <param name="requestedWidth">The requested width, or 0 to use the limit.</param>
    /// <param name="requestedHeight">The requested height, or 0 to use the limit.</param>
    /// <param name="requestedFps">The requested frame rate, or 0 to use the limit.</param>
    /// <param name="maxWidth">The agent's <c>max_video_width</c>.</param>
    /// <param name="maxHeight">The agent's <c>max_video_height</c>.</param>
    /// <param name="maxFps">The agent's <c>max_video_fps</c>.</param>
    /// <param name="screenWidth">The device screen width, or 0 when unknown.</param>
    /// <param name="screenHeight">The device screen height, or 0 when unknown.</param>
    /// <returns>The geometry to use.</returns>
    /// <remarks>
    /// <para>
    /// The rule is: honour the requested <i>height</i>, capped by the screen
    /// height, and derive the width from the device's own aspect ratio. The
    /// controller asks how tall a picture it wants; the device's screen decides
    /// how wide that picture is.
    /// </para>
    /// <para>
    /// The worked case in the vectors is a 1920x1080 request on a 1080x2400
    /// screen giving 486x1080. The height 1080 is the smaller of the request and
    /// the screen, and 486 is that height times the screen's 1080/2400 ratio.
    /// Fitting the request into the screen box instead would give 1080x607, a
    /// landscape stream of a portrait screen: correct arithmetic, wrong result,
    /// because it would letterbox the device into a strip of its own display.
    /// </para>
    /// <para>
    /// Both dimensions are forced even because H.264 codes chroma in 2x2 blocks:
    /// an odd dimension is not merely inefficient, it is unencodable.
    /// </para>
    /// <para>
    /// Clamping rather than refusing is what lets a controller ask for
    /// 2560x1440 on a device that caps at 1920x1080 and still get a stream,
    /// which is the common case when a controller has a default it did not
    /// tailor to this device.
    /// </para>
    /// </remarks>
    public static VideoGeometry ClampVideoGeometry(
        int requestedWidth,
        int requestedHeight,
        int requestedFps,
        int maxWidth,
        int maxHeight,
        int maxFps,
        int screenWidth = 0,
        int screenHeight = 0)
    {
        if (maxWidth <= 0 || maxHeight <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxWidth), "the agent's video ceiling must be positive");
        }

        // A request of zero means "use your ceiling", which is what an agent
        // that does not care should send.
        int wantWidth = requestedWidth > 0 ? requestedWidth : maxWidth;
        int wantHeight = requestedHeight > 0 ? requestedHeight : maxHeight;

        int width;
        int height = wantHeight;
        string clampedBy = "requested";

        // Never encode more pixels than the screen has: the extra ones would be
        // upscaled content and would waste the bitrate budget.
        if (screenWidth > 0 && screenHeight > 0)
        {
            height = Math.Min(wantHeight, screenHeight);
            width = (int)Math.Floor(height * ((double)screenWidth / screenHeight));
            clampedBy = height == wantHeight ? "requested" : "screen";
        }
        else
        {
            width = wantWidth;
        }

        if (width > maxWidth)
        {
            double scale = (double)maxWidth / width;
            width = maxWidth;
            height = (int)Math.Floor(height * scale);
            clampedBy = "agent_max_width";
        }

        if (height > maxHeight)
        {
            double scale = (double)maxHeight / height;
            height = maxHeight;
            width = (int)Math.Floor(width * scale);
            clampedBy = "agent_max_height";
        }

        // H.264 requires even dimensions, so round down to the nearest even
        // number and never to zero.
        width = Math.Max(2, width - (width % 2));
        height = Math.Max(2, height - (height % 2));

        int fps = requestedFps > 0 ? Math.Min(requestedFps, maxFps) : maxFps;

        return new VideoGeometry(width, height, fps, clampedBy);
    }

    /// <summary>
    /// Clamps a shell deadline to the agent's maximum.
    /// </summary>
    /// <param name="requestedTimeoutMs">The requested deadline, or 0 for the default.</param>
    /// <param name="agentShellTimeoutMs">The agent's <c>shell_timeout_ms</c>.</param>
    /// <returns>The deadline that will be applied.</returns>
    /// <remarks>
    /// Clamped rather than refused: a command that asked for ten minutes and
    /// runs for thirty seconds has still run, and refusing it outright would
    /// only make the operator retry with a smaller number.
    /// </remarks>
    public static int ClampShellTimeout(int requestedTimeoutMs, int agentShellTimeoutMs)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(agentShellTimeoutMs);

        return requestedTimeoutMs > 0
            ? Math.Min(requestedTimeoutMs, agentShellTimeoutMs)
            : agentShellTimeoutMs;
    }

    /// <summary>
    /// Checks a file chunk size against the agent's maximum.
    /// </summary>
    /// <param name="chunkSize">The declared chunk size.</param>
    /// <param name="maxFileChunk">The agent's <c>max_file_chunk</c>.</param>
    /// <returns><see langword="null"/> when acceptable, or the error to report.</returns>
    /// <remarks>
    /// Refused rather than clamped, and refused before any allocation. The limit
    /// exists to bound memory, so a request over it must not cause the buffer to
    /// be sized at all.
    /// </remarks>
    public static ErrorCode? ValidateFileChunk(int chunkSize, int maxFileChunk)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(chunkSize);

        if (chunkSize > maxFileChunk)
        {
            return ErrorCodes.FrameTooLarge;
        }

        return null;
    }

    /// <summary>
    /// Checks a gesture step count against the agent's maximum.
    /// </summary>
    /// <param name="stepCount">The number of steps in the gesture.</param>
    /// <param name="maxGestureSteps">The agent's <c>max_gesture_steps</c>.</param>
    /// <returns><see langword="null"/> when acceptable, or the error to report.</returns>
    /// <remarks>
    /// RFC-0001 section 8.2 requires <c>ERR_RESOURCE_EXHAUSTED</c> here rather
    /// than a size error, because an over-long gesture is a playback cost rather
    /// than a buffer cost. This is the rule that originally depended on a limit
    /// the RFC never declared.
    /// </remarks>
    public static ErrorCode? ValidateGestureSteps(int stepCount, int maxGestureSteps)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(stepCount);

        if (stepCount > maxGestureSteps)
        {
            return ErrorCodes.ResourceExhausted;
        }

        return null;
    }
}
