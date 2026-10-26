"""Decode any common audio format (webm/opus from browsers, WhatsApp .opus voice notes, m4a, mp3, wav)
into 16 kHz mono float32 samples. PyAV bundles its own FFmpeg, so no system install is needed."""

import io

import av
import numpy as np

TARGET_SR = 16_000


class AudioDecodeError(ValueError):
    pass


def decode_audio(data: bytes, max_seconds: int) -> np.ndarray:
    try:
        container = av.open(io.BytesIO(data))
    except (av.FFmpegError, ValueError) as exc:
        raise AudioDecodeError("We couldn't read this audio file. Try WAV, MP3, M4A, OGG/Opus or WebM.") from exc

    with container:
        if not container.streams.audio:
            raise AudioDecodeError("This file doesn't contain any audio.")
        stream = container.streams.audio[0]
        resampler = av.AudioResampler(format="flt", layout="mono", rate=TARGET_SR)
        chunks: list[np.ndarray] = []
        total = 0
        limit = max_seconds * TARGET_SR
        try:
            for frame in container.decode(stream):
                for out in resampler.resample(frame):
                    arr = out.to_ndarray().reshape(-1)
                    chunks.append(arr)
                    total += arr.size
                if total >= limit:
                    break
            for out in resampler.resample(None):
                chunks.append(out.to_ndarray().reshape(-1))
        except av.FFmpegError as exc:
            if not chunks:
                raise AudioDecodeError("This audio file seems to be damaged.") from exc

    if not chunks:
        raise AudioDecodeError("This audio file is empty.")
    audio = np.concatenate(chunks).astype(np.float32)[:limit]
    peak = float(np.max(np.abs(audio))) if audio.size else 0.0
    if peak > 1.0:
        audio /= peak
    return audio
