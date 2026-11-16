mod common;
use anyhow::{Result, ensure};
use common::*;
use oxcrypt_core::vault::{operations::VaultOperations, path::DirId};
use starcrypt::{create_vault, extract_vault};
use std::fs;

#[test]
fn corruption_in_a_later_parallel_batch_cleans_all_output() -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested"))?;
    let bytes = vec![42; 8 * 1024 * 1024 + 19];
    fs::write(source.join("nested/large"), &bytes)?;
    for index in 0..32 {
        fs::write(source.join(format!("small-{index}")), b"other file")?;
    }
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let ops = VaultOperations::open(&vault, "test password")?;
    let (parent, name) = ops.resolve_parent_path("nested/large")?;
    let path = ops.find_file(&parent, &name)?.unwrap().encrypted_path;
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    // First payload byte of the third 1 MiB batch, beyond the initial reader.
    let offset = 68 + 64 * (32_768 + 28) + 12;
    file.seek(SeekFrom::Start(offset))?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&byte)?;
    let output = temp.path().join("output");
    let error = extract_vault(&vault, &output, "test password").unwrap_err();
    ensure!(format!("{error:#}").contains("Cannot decrypt encrypted file"));
    ensure!(!output.exists());
    ensure!(fs::read(source.join("nested/large"))? == bytes);
    Ok(())
}

#[test]
#[cfg(unix)]
fn corruption_is_rejected_without_incomplete_output() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("child"))?;
    fs::write(
        source.join("payload"),
        (0..65_536).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    )?;
    fs::write(source.join("child/data"), b"nested")?;
    let long = "l".repeat(180);
    fs::write(source.join(&long), b"long-name")?;
    std::os::unix::fs::symlink("payload", source.join("link"))?;
    let base = temp.path().join("base");
    create_vault(&source, &base, "test password")?;
    let ops = VaultOperations::open(&base, "test password")?;
    let storage = ops.calculate_directory_storage_path(&DirId::root())?;
    let file = ops
        .find_file(&DirId::root(), "payload")?
        .unwrap()
        .encrypted_path
        .strip_prefix(&base)?
        .to_owned();
    let link = ops
        .find_symlink(&DirId::root(), "link")?
        .unwrap()
        .encrypted_path
        .strip_prefix(&base)?
        .to_owned();
    let directory = ops.find_directory(&DirId::root(), "child")?.unwrap();
    let child_entry = directory.encrypted_path.strip_prefix(&base)?.to_owned();
    let child_storage = ops
        .calculate_directory_storage_path(&directory.directory_id)?
        .strip_prefix(&base)?
        .to_owned();
    let shortened = fs::read_dir(&storage)?
        .find_map(|e| {
            let path = e.ok()?.path();
            (path.extension()?.to_str()? == "c9s")
                .then(|| path.strip_prefix(&base).unwrap().to_owned())
        })
        .unwrap();
    let source_bytes = fs::read(source.join("payload"))?;
    let cases = [
        "jwt-signature",
        "masterkey",
        "header",
        "chunk-payload",
        "chunk-tag",
        "truncated-tag",
        "short-chunk",
        "appended-short-chunk",
        "reordered-chunks",
        "duplicated-chunk",
        "invalid-name",
        "missing-short-name",
        "changed-short-name",
        "corrupt-symlink",
        "missing-directory-id",
        "missing-child-storage",
        "ambiguous-entry",
        "native-symlink-payload",
        "escaping-masterkey",
    ];
    for name in cases {
        let vault = temp.path().join(name);
        copy_tree(&base, &vault)?;
        let payload = vault.join(&file);
        match name {
            "jwt-signature" => {
                let mut token = fs::read(vault.join("vault.cryptomator"))?;
                let at = token.iter().rposition(|b| *b == b'.').unwrap() + 1;
                token[at] = if token[at] == b'A' { b'B' } else { b'A' };
                fs::write(vault.join("vault.cryptomator"), token)?;
            }
            "masterkey" => fs::write(vault.join("masterkey.cryptomator"), b"{broken-json")?,
            "header" | "chunk-payload" | "chunk-tag" | "corrupt-symlink" => {
                let path = if name == "corrupt-symlink" {
                    vault.join(&link).join("symlink.c9r")
                } else {
                    payload
                };
                let mut bytes = fs::read(&path)?;
                let at = match name {
                    "header" => 20,
                    "chunk-payload" => 68 + 12,
                    _ => bytes.len() - 1,
                };
                bytes[at] ^= 1;
                fs::write(path, bytes)?;
            }
            "truncated-tag"
            | "short-chunk"
            | "appended-short-chunk"
            | "reordered-chunks"
            | "duplicated-chunk" => {
                let mut bytes = fs::read(&payload)?;
                match name {
                    "truncated-tag" => {
                        bytes.pop();
                    }
                    "short-chunk" => bytes.truncate(68 + 10),
                    "appended-short-chunk" => bytes.push(1),
                    "reordered-chunks" => {
                        let first = bytes[68..68 + 32_796].to_vec();
                        let second = bytes[68 + 32_796..].to_vec();
                        bytes.truncate(68);
                        bytes.extend(second);
                        bytes.extend(first);
                    }
                    "duplicated-chunk" => {
                        let first = bytes[68..68 + 32_796].to_vec();
                        bytes[68 + 32_796..].copy_from_slice(&first);
                    }
                    _ => unreachable!(),
                }
                fs::write(payload, bytes)?;
            }
            "invalid-name" => fs::rename(&payload, payload.parent().unwrap().join("invalid.c9r"))?,
            "missing-short-name" => fs::remove_file(vault.join(&shortened).join("name.c9s"))?,
            "changed-short-name" => {
                fs::write(vault.join(&shortened).join("name.c9s"), "tampered.c9r")?
            }
            "missing-directory-id" => fs::remove_file(vault.join(&child_entry).join("dir.c9r"))?,
            "missing-child-storage" => fs::remove_dir_all(vault.join(&child_storage))?,
            "ambiguous-entry" => fs::write(vault.join(&link).join("dir.c9r"), "ambiguous")?,
            "native-symlink-payload" => {
                fs::remove_file(&payload)?;
                std::os::unix::fs::symlink(source.join("payload"), &payload)?;
            }
            "escaping-masterkey" => {
                let token = fs::read_to_string(vault.join("vault.cryptomator"))?;
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
                validation.required_spec_claims.clear();
                let claims: serde_json::Value =
                    ops.master_key().validate_jwt(&token, &validation)?;
                let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
                header.kid = Some("masterkeyfile:../base/masterkey.cryptomator".into());
                fs::write(
                    vault.join("vault.cryptomator"),
                    jsonwebtoken::encode(
                        &header,
                        &claims,
                        &ops.master_key().create_jwt_encoding_key()?,
                    )?,
                )?;
            }
            _ => unreachable!(),
        }
        let output = temp.path().join(format!("output-{name}"));
        let result = extract_vault(&vault, &output, "test password");
        ensure!(result.is_err(), "Corruption was silently accepted: {name}");
        ensure!(!output.exists(), "Incomplete output remains: {name}");
    }
    ensure!(
        fs::read(source.join("payload"))? == source_bytes,
        "Source changed during malformed-vault tests"
    );
    Ok(())
}
#[test]
fn whole_chunk_truncation_is_a_format_limit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    let bytes = (0..65_536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(source.join("payload"), &bytes)?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let ops = VaultOperations::open(&vault, "test password")?;
    let encrypted = ops
        .find_file(&DirId::root(), "payload")?
        .unwrap()
        .encrypted_path;
    fs::OpenOptions::new()
        .write(true)
        .open(encrypted)?
        .set_len(68 + 32_796)?;
    let output = temp.path().join("output");
    extract_vault(&vault, &output, "test password")?;
    ensure!(fs::read(output.join("payload"))? == bytes[..32_768]);
    // No authenticated total file length exists in this format. Removing an
    // entire trailing chunk cannot be distinguished from a shorter valid file.
    Ok(())
}
#[test]
fn older_empty_file_chunks_are_authenticated_before_reading() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("empty"), [])?;
    let vault = temp.path().join("vault");
    create_vault(&source, &vault, "test password")?;
    let ops = VaultOperations::open(&vault, "test password")?;
    let path = ops
        .find_file(&DirId::root(), "empty")?
        .unwrap()
        .encrypted_path;
    let mut old = ops.cipher_combo().encrypt_file(b"", ops.master_key())?;
    fs::write(&path, &old)?;
    let valid = temp.path().join("valid");
    extract_vault(&vault, &valid, "test password")?;
    ensure!(fs::metadata(valid.join("empty"))?.len() == 0);
    *old.last_mut().unwrap() ^= 1;
    fs::write(&path, old)?;
    let invalid = temp.path().join("invalid");
    ensure!(extract_vault(&vault, &invalid, "test password").is_err());
    ensure!(!invalid.exists());
    Ok(())
}
