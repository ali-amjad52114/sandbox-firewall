"""Build a ~2 minute product demo from live console screenshots."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import edge_tts
import imageio_ffmpeg

ROOT = Path(__file__).resolve().parent
STILLS = ROOT / "stills"
AUDIO = ROOT / "audio"
OUT = ROOT / "sandbox-firewall-2min.mp4"
CONCAT = ROOT / "concat.txt"
VOICE = "en-US-AndrewMultilingualNeural"

BEATS = [
    (
        "01-dashboard.png",
        "This is the Execution Firewall Console. Sandbox Firewall is an execution firewall for AI agents, built on the Wasmer SDK. Every time an agent wants to run code, that run becomes a trace you can open.",
    ),
    (
        "02-form.png",
        "The product is one action. Paste the code. Choose Python, Node, or PHP. Choose a policy. Click Run in sandbox.",
    ),
    (
        "03-clean.png",
        "Here is a clean run: print hello from the Wasmer sandbox. Verdict clean. The runner field says Wasmer. Network is off. Only the out directory is writable. stdout is the hello line. No violations.",
    ),
    (
        "03-clean.png",
        "How Wasmer is used. We create a fresh sandbox with the Wasmer SDK. Guest packages for the language. The program lives under workspace. Policy environment and fake canary secrets go in. The first sandbox in a process takes about six seconds to start the engine. This run shows create six seconds, exec about one second. After that, creating a sandbox is under a millisecond.",
    ),
    (
        "04-blocked.png",
        "The guest never talks to the internet on its own. Wasmer's host network bridge lives on our side. We intercept every resolve and TCP connect. Strict policy can turn the network off, or allow a short list of hosts.",
    ),
    (
        "05-violations.png",
        "Same console. A program that asks to resolve a collector host. Policy says no. The connection never happens. Verdict blocked. You see a high network.blocked violation, and a network event marked denied.",
    ),
    (
        "01-dashboard.png",
        "Counts update live. Blocked, clean, average sandbox create, average exec. Attach the gateway as an MCP server and every run_code call takes this path.",
    ),
    (
        "02-form.png",
        "Sandbox first. Policy second. Evidence third. Wasmer is the isolation. The console is how you see it. One line of config to turn it on.",
    ),
]


async def synth() -> list[tuple[Path, Path, float]]:
    AUDIO.mkdir(exist_ok=True)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    clips: list[tuple[Path, Path, float]] = []
    for i, (still_name, text) in enumerate(BEATS, start=1):
        still = STILLS / still_name
        if not still.exists():
            raise FileNotFoundError(still)
        wav = AUDIO / f"{i:02d}.mp3"
        if not wav.exists() or wav.stat().st_size < 1000:
            communicate = edge_tts.Communicate(text, VOICE, rate="-4%")
            await communicate.save(str(wav))
        probe = subprocess.run([ffmpeg, "-i", str(wav), "-hide_banner"], capture_output=True, text=True)
        duration = parse_duration(probe.stderr)
        clips.append((still, wav, duration + 0.35))
    return clips


def parse_duration(stderr: str) -> float:
    for line in stderr.splitlines():
        if "Duration:" in line:
            raw = line.split("Duration:")[1].split(",")[0].strip()
            h, m, s = raw.split(":")
            return int(h) * 3600 + int(m) * 60 + float(s)
    raise RuntimeError(f"Could not parse duration from ffmpeg:\n{stderr}")


def assemble(clips: list[tuple[Path, Path, float]]) -> None:
    """One encode: Main-profile H.264 + 48 kHz stereo AAC (Windows/Cursor-safe)."""
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    cmd: list[str] = [ffmpeg, "-y"]
    filter_parts: list[str] = []
    concat_in: list[str] = []
    for i, (still, wav, seconds) in enumerate(clips):
        cmd += ["-loop", "1", "-t", f"{seconds:.3f}", "-i", str(still), "-i", str(wav)]
        vi, ai = i * 2, i * 2 + 1
        filter_parts.append(
            f"[{vi}:v]scale=1920:1080:force_original_aspect_ratio=decrease,"
            f"pad=1920:1080:(ow-iw)/2:(oh-ih)/2:#0f1115,fps=30,format=yuv420p,"
            f"setpts=PTS-STARTPTS[v{i}]"
        )
        filter_parts.append(
            f"[{ai}:a]aformat=sample_rates=48000:channel_layouts=stereo,"
            f"aresample=async=1,apad,atrim=0:{seconds:.3f},asetpts=PTS-STARTPTS[a{i}]"
        )
        concat_in.append(f"[v{i}][a{i}]")
    n = len(clips)
    graph = ";".join(filter_parts) + ";" + "".join(concat_in) + f"concat=n={n}:v=1:a=1[v][a]"
    cmd += [
        "-filter_complex",
        graph,
        "-map",
        "[v]",
        "-map",
        "[a]",
        "-c:v",
        "libx264",
        "-profile:v",
        "main",
        "-level",
        "4.0",
        "-pix_fmt",
        "yuv420p",
        "-preset",
        "fast",
        "-crf",
        "20",
        "-c:a",
        "aac",
        "-ar",
        "48000",
        "-ac",
        "2",
        "-b:a",
        "192k",
        "-movflags",
        "+faststart",
        str(OUT),
    ]
    run = subprocess.run(cmd, capture_output=True, text=True)
    if run.returncode != 0:
        raise RuntimeError(run.stderr[-4000:])
    probe = subprocess.run([ffmpeg, "-i", str(OUT), "-hide_banner"], capture_output=True, text=True)
    print(OUT)
    print(probe.stderr)


if __name__ == "__main__":
    clips = asyncio.run(synth())
    total = sum(s for _, _, s in clips)
    print("beat durations:", [round(s, 2) for _, _, s in clips], "total", round(total, 2))
    assemble(clips)
