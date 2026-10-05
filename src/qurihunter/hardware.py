from __future__ import annotations

import json
import platform
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Hardware:
    ram_gb: float
    cpu: str
    cores: int
    gpu: str | None = None
    vram_gb: float = 0.0
    unified: bool = False  # Apple Silicon: GPU shares system RAM

    def describe(self) -> str:
        g = f"{self.gpu} ({self.vram_gb:.1f} GB VRAM)" if self.gpu and self.vram_gb else (self.gpu or "none detected")
        return f"CPU: {self.cpu} ({self.cores} cores) · RAM: {self.ram_gb:.1f} GB · GPU: {g}"


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _ram_gb() -> float:
    try:
        import psutil
        return psutil.virtual_memory().total / 1024**3
    except ImportError:
        try:
            for line in open("/proc/meminfo"):
                if line.startswith("MemTotal"):
                    return int(line.split()[1]) / 1024**2
        except OSError:
            pass
    return 0.0


def detect() -> Hardware:
    import os
    hw = Hardware(ram_gb=_ram_gb(), cpu=platform.processor() or platform.machine(), cores=os.cpu_count() or 1)
    if shutil.which("nvidia-smi"):
        out = _run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
        best = None
        for line in out.strip().splitlines():
            try:
                name, mem = [x.strip() for x in line.rsplit(",", 1)]
                if best is None or float(mem) > best[1]:
                    best = (name, float(mem))
            except ValueError:
                continue
        if best:
            hw.gpu, hw.vram_gb = best[0], best[1] / 1024
            return hw
    if shutil.which("rocm-smi"):
        out = _run(["rocm-smi", "--showproductname", "--showmeminfo", "vram", "--json"])
        try:
            data = json.loads(out)
            card = next(iter(data.values()))
            hw.gpu = card.get("Card series") or card.get("Card Series") or "AMD GPU"
            hw.vram_gb = int(card.get("VRAM Total Memory (B)", 0)) / 1024**3
            return hw
        except (ValueError, StopIteration, AttributeError):
            pass
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        hw.gpu, hw.unified = "Apple Silicon (unified memory)", True
        hw.vram_gb = hw.ram_gb * 0.65  # usable share for Metal
        return hw
    if shutil.which("lspci"):  # name only; VRAM unknown -> treated as CPU-only
        for line in _run(["lspci"]).splitlines():
            if "VGA" in line or "3D controller" in line:
                hw.gpu = line.split(": ", 1)[-1][:60]
                break
    return hw


def recommend_model(hw: Hardware) -> tuple[str, str]:
    """(ollama model tag, reason)."""
    if hw.vram_gb >= 10:
        return "llama3.1:8b", f"{hw.vram_gb:.0f} GB VRAM fits Llama 3.1 8B comfortably"
    if hw.vram_gb >= 5.5:
        return "mistral:7b", f"{hw.vram_gb:.0f} GB VRAM fits Mistral 7B (4-bit)"
    if hw.ram_gb >= 6:
        return "phi3:mini", "no usable GPU: Phi-3 Mini (3.8B) runs well on CPU"
    return "qwen2.5:1.5b", f"only {hw.ram_gb:.0f} GB RAM: using a very small model"
