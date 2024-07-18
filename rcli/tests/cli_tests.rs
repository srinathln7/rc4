use assert_cmd::Command;
use std::fs;


#[test]
fn test_encrypt_and_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("secret.txt");
    
    // Create a temporary file with some content
    std::fs::write(&file_path, "This is a secret").unwrap();
    
    let key = ["0x4b", "0x8e", "0x29", "0x87", "0x80"];
    
    // Run the encryption command
    Command::cargo_bin("rcli")
        .unwrap()
        .args(&["--file", file_path.to_str().unwrap()])
        .arg("--key")
        .args(&key)
        .assert()
        .success()
        .stdout(predicates::str::contains("Encrypted"));

    // Check that the file is encrypted (not containing the original text)
    let encrypted_contents = std::fs::read(&file_path).unwrap();
    assert_ne!(encrypted_contents, b"This is a secret");

    // Run the decryption command
    Command::cargo_bin("rcli")
        .unwrap()
        .args(&["--file", file_path.to_str().unwrap()])
        .arg("--key")
        .args(&key)
        .assert()
        .success()
        .stdout(predicates::str::contains("Decrypted"));

    // Check that the file is decrypted back to the original text
    let decrypted_contents = std::fs::read(&file_path).unwrap();
    assert_eq!(decrypted_contents, b"This is a secret");
}


#[test]
fn test_invalid_key() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("secret.txt");
    
    // Create a temporary file with some content
    fs::write(&file_path, "This is a secret").unwrap();
    
    let invalid_key = "invalid_key";

    // Run the command with an invalid key
    Command::cargo_bin("rcli")
        .unwrap()
        .args(&["--file", file_path.to_str().unwrap(), "--key", invalid_key])
        .assert()
        .failure();
}

#[test]
fn test_recursive_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let sub_dir = dir.path().join("subdir");
    fs::create_dir(&sub_dir).unwrap();
    
    let file_path1 = sub_dir.join("file1.txt");
    let file_path2 = sub_dir.join("file2.txt");
    
    // Create temporary files with some content
    fs::write(&file_path1, "This is file 1").unwrap();
    fs::write(&file_path2, "This is file 2").unwrap();
    
    let key = ["0x4b", "0x8e", "0x29", "0x87", "0x80"];
    
    // Run the recursive encryption command
    Command::cargo_bin("rcli")
        .unwrap()
        .args(&["--file", dir.path().to_str().unwrap()])
        .arg("--key")
        .args(&key)
        .arg("--recursive")
        .assert()
        .success()
        .stdout(predicates::str::contains("Encrypted"));

    // Check that the files are encrypted (not containing the original text)
    let encrypted_contents1 = fs::read(&file_path1).unwrap();
    let encrypted_contents2 = fs::read(&file_path2).unwrap();
    assert_ne!(encrypted_contents1, b"This is file 1");
    assert_ne!(encrypted_contents2, b"This is file 2");

    // Run the recursive decryption command
    Command::cargo_bin("rcli")
        .unwrap()
        .args(&["--file", dir.path().to_str().unwrap()])
        .arg("--key")
        .args(&key)
        .arg("--recursive")
        .assert()
        .success()
        .stdout(predicates::str::contains("Decrypted"));

    // Check that the files are decrypted back to the original text
    let contents1 = fs::read(&file_path1).unwrap();
    let contents2 = fs::read(&file_path2).unwrap();
    assert_eq!(contents1, b"This is file 1");
    assert_eq!(contents2, b"This is file 2");
}
