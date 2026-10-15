//! Library side of the `ra` CLI, shared with the regression tests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ra_analysis::Options;
use ra_compare::{Comparison, Thresholds, Violation};
use ra_core::AnalysisReport;

/// Loads, analyzes and reports one binary.
pub fn analyze_file(
    path: &Path,
    language: Option<&str>,
    processors: &Path,
    opts: &Options,
) -> Result<AnalysisReport> {
    let prog = ra_loader::load_path(path, language)?;
    let lang = ra_sleigh::Language::load(processors, &prog.language)
        .with_context(|| format!("loading language {}", prog.language))?;
    let analysis = ra_analysis::analyze(&prog, &lang, opts);
    let mut report = ra_analysis::report(&prog, &analysis);
    report.binary.path = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(report)
}

pub struct RegressConfig {
    pub corpus: PathBuf,
    pub expected: PathBuf,
    pub thresholds: PathBuf,
    pub processors: PathBuf,
    pub report_dir: Option<PathBuf>,
    pub update_thresholds: bool,
    pub filter: Option<String>,
}

pub struct RegressOutcome {
    pub results: Vec<Comparison>,
    pub violations: Vec<Violation>,
    /// Corpus binaries with no Ghidra export to compare against.
    pub missing_expected: Vec<String>,
    pub markdown: String,
}

/// Analyzes every corpus binary that has a Ghidra export, compares the two,
/// and checks (or ratchets) the thresholds.
pub fn regress(cfg: &RegressConfig) -> Result<RegressOutcome> {
    let mut bins: Vec<PathBuf> = std::fs::read_dir(&cfg.corpus)
        .with_context(|| format!("reading corpus {}", cfg.corpus.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|e| e != "log"))
        .collect();
    bins.sort();
    let mut results = vec![];
    let mut missing_expected = vec![];
    for bin in bins {
        let name = bin.file_name().unwrap().to_string_lossy().into_owned();
        if cfg
            .filter
            .as_ref()
            .is_some_and(|f| !name.contains(f.as_str()))
        {
            continue;
        }
        let Some(expected) = ra_compare::expected_path(&cfg.expected, &name) else {
            missing_expected.push(name);
            continue;
        };
        let ghidra = ra_compare::load_report(&expected)?;
        let ours = analyze_file(&bin, None, &cfg.processors, &Options::default())
            .with_context(|| format!("analyzing {name}"))?;
        if let Some(dir) = &cfg.report_dir {
            std::fs::create_dir_all(dir)?;
            std::fs::write(
                dir.join(format!("{name}.ra.json")),
                serde_json::to_string_pretty(&ours)?,
            )?;
        }
        results.push(ra_compare::compare(&name, &ghidra, &ours));
    }
    let mut thresholds = Thresholds::load(&cfg.thresholds)?;
    if cfg.update_thresholds {
        for c in &results {
            thresholds.ratchet(c);
        }
        thresholds.save(&cfg.thresholds)?;
    }
    let violations: Vec<Violation> = results.iter().flat_map(|c| thresholds.check(c)).collect();
    let markdown = ra_compare::markdown(&results, &violations);
    if let Some(dir) = &cfg.report_dir {
        std::fs::write(dir.join("report.md"), &markdown)?;
        std::fs::write(
            dir.join("report.json"),
            serde_json::to_string_pretty(&results)?,
        )?;
    }
    Ok(RegressOutcome {
        results,
        violations,
        missing_expected,
        markdown,
    })
}
