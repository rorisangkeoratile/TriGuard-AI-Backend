from fastapi import HTTPException, UploadFile, status

from app.config import get_settings


async def read_upload(file: UploadFile, allowed_prefixes: tuple[str, ...] = ()) -> bytes:
    """Read an upload fully, enforcing the size limit and (optionally) the content type."""
    max_bytes = get_settings().max_upload_mb * 1024 * 1024
    content_type = (file.content_type or "").lower()
    if allowed_prefixes and content_type and not content_type.startswith(allowed_prefixes) \
            and content_type != "application/octet-stream":
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"Unsupported file type: {content_type}")
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"File is larger than {get_settings().max_upload_mb} MB.")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The file is empty.")
    return data
