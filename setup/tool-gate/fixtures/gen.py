from pathlib import Path

out = Path("build")
out.mkdir(exist_ok=True)
rows = sorted(p.name for p in Path("src").glob("*.md"))
(out / "report.md").write_text("# Report\n\n" + "\n".join(f"- {r}" for r in rows) + "\n")
print(f"wrote {len(rows)} rows")
