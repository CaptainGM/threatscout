from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatscout.engine import ThreatScoutEngine
from threatscout.models import RiskLevel
from threatscout.report import save_html, save_json, to_json

console = Console(force_terminal=True)

STYLES = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "blue",
    RiskLevel.CLEAN: "green",
}


def _show(report) -> None:
    style = STYLES.get(report.risk_level, "white")
    console.print(Panel(
        f"[{style}]{report.risk_level.value}[/{style}]  "
        f"Skor: [bold]{report.threat_score}[/bold]/100\n"
        f"IOC: {report.ioc} ({report.ioc_type.value})",
        title="ThreatScout",
    ))
    table = Table(title="Provider Sonuclari")
    table.add_column("Provider", style="cyan")
    table.add_column("Durum")
    table.add_column("Cache")
    for p in report.providers:
        status = "[green]OK[/green]" if p.success else f"[red]{p.error}[/red]"
        table.add_row(p.provider.title(), status, "Evet" if p.cached else "Hayir")
    console.print(table)
    if report.tags:
        console.print(f"Etiketler: {', '.join(report.tags[:15])}")


async def _scan(ioc: str, no_cache: bool, fmt: str, output: str | None):
    engine = ThreatScoutEngine()
    try:
        report = await engine.enrich(ioc, use_cache=not no_cache)
        _show(report)
        if fmt == "json":
            console.print(to_json(report) if not output else f"Kaydedildi: {save_json(report, output)}")
        elif fmt == "html":
            path = save_html(report, output or f"reports/{ioc.replace('/', '_')}.html")
            console.print(f"HTML: {path}")
    finally:
        await engine.close()


@click.group()
def cli():
    pass


@cli.command()
@click.argument("ioc")
@click.option("--no-cache", is_flag=True)
@click.option("--format", "fmt", type=click.Choice(["table", "json", "html"]), default="table")
@click.option("-o", "--output")
def scan(ioc: str, no_cache: bool, fmt: str, output: str | None):
    asyncio.run(_scan(ioc, no_cache, fmt, output))


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--no-cache", is_flag=True)
@click.option("-d", "--output-dir", default="reports")
def batch(file: str, no_cache: bool, output_dir: str):
    iocs = [
        l.strip() for l in Path(file).read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.startswith("#")
    ]

    async def _run():
        engine = ThreatScoutEngine()
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            for ioc in iocs:
                console.rule(ioc)
                report = await engine.enrich(ioc, use_cache=not no_cache)
                _show(report)
                save_json(report, Path(output_dir) / f"{ioc.replace('/', '_')}.json")
        finally:
            await engine.close()

    asyncio.run(_run())
