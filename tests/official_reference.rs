mod common;
use anyhow::{Context, Result, ensure};
use common::compare_tree;
use oxcrypt_core::vault::{operations::VaultOperations, path::DirId};
use starcrypt::{ArchiveFormat, create_archive, create_vault, extract_vault};
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
        compare_modification_times(&source, &output, 1_000_000)?;
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
    for (extension, format) in [("zip", ArchiveFormat::Zip), ("7z", ArchiveFormat::SevenZip)] {
        create_archive(
            &source,
            root.join(format!("starcrypt.{extension}")),
            "archive-test-password",
            format,
        )?;
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

// Java providers expose millisecond precision. Archive paths additionally use
// their documented precision; this does not relax content/link comparisons.
fn compare_modification_times(
    source: &std::path::Path,
    output: &std::path::Path,
    quantum: u128,
) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = output.join(entry.file_name());
        if kind.is_symlink() {
            continue;
        }
        let expected = entry
            .metadata()?
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let actual = fs::metadata(&path)?
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        ensure!(
            expected / quantum == actual / quantum,
            "Modification time mismatch: {}",
            path.display()
        );
        if kind.is_dir() {
            compare_modification_times(&entry.path(), &path, quantum)?;
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires Java-edited and externally packaged fixtures; run tests/interop/run.py"]
fn official_java_modified_and_archived_vaults() -> Result<()> {
    let root = PathBuf::from(std::env::var("STARCRYPT_VERIFICATION_DIR")?).canonicalize()?;
    for name in ["gcm", "ctrmac"] {
        let source = root.join(format!("edited-source-{name}"));
        let output = root.join(format!("edited-output-{name}"));
        extract_vault(
            root.join(format!("editable-{name}")),
            &output,
            "reference-café-🌎",
        )?;
        compare_tree(&source, &output)?;
        compare_modification_times(&source, &output, 1_000_000)?;
    }
    for extension in ["zip", "7z"] {
        let output = root.join(format!("external-output-{extension}"));
        extract_vault(
            root.join(format!("external-java.{extension}")),
            &output,
            "reference-café-🌎",
        )?;
        compare_tree(&root.join("source"), &output)?;
        compare_modification_times(
            &root.join("source"),
            &output,
            if extension == "zip" {
                2_000_000_000
            } else {
                1_000_000
            },
        )?;
    }
    Ok(())
}

#[test]
#[cfg(unix)]
fn frozen_official_release_fixtures() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/interop/reference");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
    let cases = manifest["cases"]
        .as_array()
        .context("Missing historical fixture cases")?;
    ensure!(
        cases.len() == 2,
        "Both frozen cipher suites must be present"
    );
    for case in cases {
        let temp = tempfile::tempdir()?;
        let archive = root.join(case["archive"].as_str().context("Missing archive")?);
        let password = case["password"]
            .as_str()
            .context("Missing fixture password")?;
        let output = temp.path().join("output");
        extract_vault(&archive, &output, password)?;
        let expected = temp.path().join("expected");
        fs::create_dir_all(expected.join("nested/empty"))?;
        for (name, content) in [
            ("empty", vec![]),
            ("boundary", (0..32769).map(|i| (i % 251) as u8).collect()),
            ("nested/café 🌎", b"official historical fixture\n".to_vec()),
            (
                &format!("long-{}", "x".repeat(180)),
                b"shortened filename\n".to_vec(),
            ),
        ] {
            fs::write(expected.join(name), content)?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink("nested/café 🌎", expected.join("relative-link"))?;
        compare_tree(&expected, &output)?;
        let wrong = temp.path().join("wrong");
        ensure!(extract_vault(&archive, &wrong, "wrong-password").is_err());
        ensure!(!wrong.exists());
    }
    Ok(())
}

#[test]
#[ignore = "requires official Java fixtures; run tests/interop/run.py"]
fn official_java_reference_metadata() -> Result<()> {
    let root = PathBuf::from(std::env::var("STARCRYPT_VERIFICATION_DIR")?).canonicalize()?;
    let password = fs::read_to_string(root.join("java-gcm-password.txt"))?;
    let mut report = Vec::new();
    for scheme in ["gcm", "ctrmac"] {
        let base = root.join(format!("java-{scheme}"));
        for mutation in ["signature", "primaryMasterKey", "hmacMasterKey"] {
            let name = format!("metadata-{scheme}-{mutation}");
            let vault = root.join(&name);
            common::copy_tree(&base, &vault)?;
            if mutation == "signature" {
                let path = vault.join("vault.cryptomator");
                let mut token = fs::read(&path)?;
                let offset = token
                    .iter()
                    .rposition(|byte| *byte == b'.')
                    .context("Missing JWT signature")?
                    + 1;
                token[offset] = if token[offset] == b'A' { b'B' } else { b'A' };
                fs::write(path, token)?;
            } else {
                let path = vault.join("masterkey.cryptomator");
                let mut key: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                let mut wrapped = key[mutation]
                    .as_str()
                    .context("Missing wrapped key")?
                    .as_bytes()
                    .to_vec();
                wrapped[0] = if wrapped[0] == b'A' { b'B' } else { b'A' };
                key[mutation] = String::from_utf8(wrapped)?.into();
                fs::write(path, serde_json::to_vec(&key)?)?;
            }
            let output = root.join(format!("rejected-{name}"));
            let error =
                extract_vault(&vault, &output, &password).expect_err("Tampered metadata accepted");
            let error = format!("{error:#}");
            ensure!(
                error.contains(if mutation == "signature" {
                    "InvalidSignature"
                } else {
                    "Key unwrap failed"
                }),
                "Unexpected metadata rejection: {error}"
            );
            ensure!(!output.exists());
            report.push(serde_json::json!({"vault": name, "scheme": if scheme == "gcm" {"SIV_GCM"} else {"SIV_CTRMAC"},
                "expected_exception": if mutation == "signature" {"VaultKeyInvalidException"} else {"InvalidPassphraseException"}}));
        }
    }
    // A correctly signed alternate key ID must not slip past the Java oracle's
    // loader merely because it already has an unlocked key in memory.
    let base = root.join("java-gcm");
    let vault = root.join("unexpected-key-id");
    common::copy_tree(&base, &vault)?;
    let ops = VaultOperations::open(&base, &password)?;
    let token = fs::read_to_string(vault.join("vault.cryptomator"))?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.required_spec_claims.clear();
    let claims: serde_json::Value = ops.master_key().validate_jwt(&token, &validation)?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("masterkeyfile:other.cryptomator".into());
    fs::write(
        vault.join("vault.cryptomator"),
        jsonwebtoken::encode(
            &header,
            &claims,
            &ops.master_key().create_jwt_encoding_key()?,
        )?,
    )?;
    fs::write(
        root.join("metadata-corruption.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
