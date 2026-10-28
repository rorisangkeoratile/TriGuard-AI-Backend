# TriGuard AI backend for Hugging Face Spaces (Docker SDK). Spaces run the container as user 1000 on port 7860.
FROM python:3.13-slim

RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    HF_HOME=/home/user/.cache/huggingface \
    PYTHONUNBUFFERED=1
WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir --user -r requirements.txt

# Download the voice-clone and transcription models during the build, so a restarted Space is ready quickly.
RUN python -c "from huggingface_hub import snapshot_download as d; \
d('mo-thecreator/Deepfake-audio-detection', allow_patterns=['*.json', '*.safetensors']); \
d('openai/whisper-base', allow_patterns=['*.json', '*.txt', '*.safetensors'])"

COPY --chown=user . .

EXPOSE 7860
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", "--forwarded-allow-ips", "*"]
