mod common;
use anyhow::{Context, Result, ensure};
use common::compare_tree;
use oxcrypt_core::vault::{operations::VaultOperations, path::DirId};
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

#[test]
#[ignore = "requires official Java fixtures; run tests/interop/run.py"]
fn official_java_reference_corruption() -> Result<()> {
    let root = PathBuf::from(std::env::var("STARCRYPT_VERIFICATION_DIR")?).canonicalize()?;
    let cases: serde_json::Value = serde_json::from_slice(&fs::read(root.join("cases.json"))?)?;
    let mut report = Vec::new();
    for case in cases.as_array().context("Cases must be an array")? {
        let name = case["name"].as_str().context("Missing case name")?;
        if !matches!(name, "java-gcm" | "java-ctrmac") {
            continue;
        }
        let password_file = case["password_file"]
            .as_str()
            .context("Missing password file")?;
        let password = fs::read_to_string(root.join(password_file))?;
        let base = root.join(name);
        let ops = VaultOperations::open(&base, &password)?;
        let file = ops
            .find_file(&DirId::root(), "bytes-65536.bin")?
            .context("Missing corruption fixture")?;
        let relative = file.encrypted_path.strip_prefix(&base)?;
        let original = fs::read(&file.encrypted_path)?;
        let (header, nonce, overhead) = if name == "java-gcm" {
            (68, 12, 28)
        } else {
            (88, 16, 48)
        };
        let chunk = 32768 + overhead;
        ensure!(
            original.len() == header + 2 * chunk,
            "Unexpected reference ciphertext geometry"
        );
        for mutation in [
            "header",
            "nonce",
            "payload",
            "tag",
            "reordered-chunks",
            "duplicated-chunk",
        ] {
            let label = format!("{name}-{mutation}");
            let vault_name = format!("corrupt-{label}");
            let vault = root.join(&vault_name);
            common::copy_tree(&base, &vault)?;
            let mut corrupted = original.clone();
            match mutation {
                "header" => corrupted[20] ^= 1,
                "nonce" => corrupted[header] ^= 1,
                "payload" => corrupted[header + nonce] ^= 1,
                "tag" => corrupted[header + chunk - 1] ^= 1,
                "reordered-chunks" => {
                    corrupted[header..header + chunk].copy_from_slice(&original[header + chunk..]);
                    corrupted[header + chunk..].copy_from_slice(&original[header..header + chunk]);
                }
                "duplicated-chunk" => {
                    corrupted[header + chunk..].copy_from_slice(&original[header..header + chunk])
                }
                _ => unreachable!(),
            }
            fs::write(vault.join(relative), corrupted)?;
            let output = root.join(format!("rejected-output-{label}"));
            let error = extract_vault(&vault, &output, &password)
                .expect_err("Reference corruption was accepted");
            ensure!(
                !output.exists(),
                "Failed extraction left plaintext output: {label}"
            );
            report.push(serde_json::json!({
                "name": label, "scheme": case["scheme"], "vault": vault_name,
                "password_file": password_file, "rust_rejected": true,
                "no_plaintext_output": true, "error": format!("{error:#}")
            }));
        }
        ensure!(
            fs::read(&file.encrypted_path)? == original,
            "Original Java fixture was modified"
        );
    }
    ensure!(report.len() == 12, "Both Java cipher suites must be tested");
    fs::write(
        root.join("rust-reference-corruption.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
