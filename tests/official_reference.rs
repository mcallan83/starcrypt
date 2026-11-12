mod common;
use anyhow::{Context, Result, ensure};
use common::compare_tree;
use starcrypt::{create_vault, extract_vault};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires official Java fixtures; run tests/interop/run.py"]
fn official_java_reference_interoperability() -> Result<()> {
    let root = PathBuf::from(std::env::var("STARCRYPT_VERIFICATION_DIR")?).canonicalize()?;
    let source = root.join("source");
    let cases: serde_json::Value = serde_json::from_slice(&fs::read(root.join("cases.json"))?)?;
    let mut report = Vec::new();
    for case in cases.as_array().context("Cases must be an array")? {
        let name = case["name"].as_str().context("Missing fixture name")?;
        let password = fs::read_to_string(root.join(case["password_file"].as_str().unwrap()))?;
        let vault = root.join(name);
        let output = root.join(format!("extracted-{name}"));
        extract_vault(&vault, &output, &password)
            .with_context(|| format!("Extracting official fixture {name}"))?;
        compare_tree(&source, &output)?;
        let wrong = root.join(format!("wrong-password-{name}"));
        ensure!(extract_vault(&vault, &wrong, "definitely-wrong-test-password").is_err());
        ensure!(!wrong.exists());
        if let Some(alternate) = case["alternate_password"].as_str() {
            let alternate_output = root.join(format!("alternate-{name}"));
            extract_vault(&vault, &alternate_output, alternate)?;
            compare_tree(&source, &alternate_output)?;
        }
        create_vault(&source, root.join(format!("starcrypt-{name}")), &password)?;
        report.push(
            serde_json::json!({"case":name,"extraction_pass":true,"wrong_password_rejected":true}),
        );
    }
    fs::write(
        root.join("rust-official-reference.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
