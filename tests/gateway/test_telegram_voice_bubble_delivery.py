import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_repo = str(Path(__file__).resolve().parents[2])
if _repo not in sys.path:
    sys.path.insert(0, _repo)


def _ensure_telegram_mock():
    if "telegram" in sys.modules and hasattr(sys.modules["telegram"], "__file__"):
        return

    mod = MagicMock()
    mod.ext.ContextTypes.DEFAULT_TYPE = type(None)
    mod.constants.ParseMode.MARKDOWN = "Markdown"
    mod.constants.ParseMode.MARKDOWN_V2 = "MarkdownV2"
    mod.constants.ParseMode.HTML = "HTML"
    mod.constants.ChatType.PRIVATE = "private"
    mod.constants.ChatType.GROUP = "group"
    mod.constants.ChatType.SUPERGROUP = "supergroup"
    mod.constants.ChatType.CHANNEL = "channel"
    mod.error.NetworkError = type("NetworkError", (OSError,), {})
    mod.error.TimedOut = type("TimedOut", (OSError,), {})
    mod.error.BadRequest = type("BadRequest", (Exception,), {})

    for name in ("telegram", "telegram.ext", "telegram.constants", "telegram.request"):
        sys.modules.setdefault(name, mod)
    sys.modules.setdefault("telegram.error", mod.error)


_ensure_telegram_mock()

from gateway.config import PlatformConfig
from plugins.platforms.telegram.adapter import TelegramAdapter


def _make_adapter():
    adapter = TelegramAdapter(PlatformConfig(enabled=True, token="test-token"))
    adapter._bot = AsyncMock()
    adapter._app = MagicMock()
    adapter._bot.send_voice = AsyncMock(return_value=MagicMock(message_id=11))
    adapter._bot.send_audio = AsyncMock(return_value=MagicMock(message_id=12))
    return adapter


@pytest.mark.asyncio
async def test_send_voice_converts_mp3_to_telegram_voice_note(monkeypatch, tmp_path):
    adapter = _make_adapter()
    source = tmp_path / "reply.mp3"
    source.write_bytes(b"ID3fakeaudio")

    converted = tmp_path / "reply.ogg"
    converted.write_bytes(b"OggSfake")

    async def _retry(sender, kwargs, metadata, reply_to_id, media_label, reset_media=None):
        return await sender(**kwargs)

    monkeypatch.setattr(adapter, "_send_with_dm_topic_reply_anchor_retry", _retry)
    monkeypatch.setattr(
        adapter,
        "_convert_audio_to_telegram_voice_note",
        lambda path: str(converted),
    )

    result = await adapter.send_voice("12345", str(source))

    assert result.success is True
    adapter._bot.send_voice.assert_awaited_once()
    adapter._bot.send_audio.assert_not_awaited()
    sent_path = adapter._bot.send_voice.call_args.kwargs["voice"].name
    assert sent_path.endswith(".ogg")


@pytest.mark.asyncio
async def test_send_voice_falls_back_to_send_audio_when_conversion_unavailable(monkeypatch, tmp_path):
    adapter = _make_adapter()
    source = tmp_path / "reply.mp3"
    source.write_bytes(b"ID3fakeaudio")

    async def _retry(sender, kwargs, metadata, reply_to_id, media_label, reset_media=None):
        return await sender(**kwargs)

    monkeypatch.setattr(adapter, "_send_with_dm_topic_reply_anchor_retry", _retry)
    monkeypatch.setattr(
        adapter,
        "_convert_audio_to_telegram_voice_note",
        lambda path: None,
    )

    result = await adapter.send_voice("12345", str(source))

    assert result.success is True
    adapter._bot.send_audio.assert_awaited_once()
    adapter._bot.send_voice.assert_not_awaited()
