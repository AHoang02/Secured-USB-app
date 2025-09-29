use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use clap::{Parser, Subcommand};
use drbg::thread::LocalCtrDrbg;
use qrcode::QrCode;
use image::Luma;
use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use bincode;

const NONCE_SIZE: usize = 12;

#[derive(Parser)]
#[command(name = "QR Guard")]
#[command(
    about = "Encrypt/decrypt with AEAD-secured metadata + PNG-QR; interactive 3-attempt decrypt"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)] input: String,
        #[arg(short, long)] output: String,
        #[arg(short = 'q', long)] qr_out: Option<String>,
        #[arg(short = 'm', long, default_value = "60")] minutes: i64,
    },
    Decrypt {
        #[arg(short, long)] input: String,
        #[arg(short, long)] output: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    original_filename: String,
    created_at: DateTime<Utc>,
    decrypt_after: DateTime<Utc>,
    decrypt_before: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedBlob {
    meta: Metadata,
    data: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { input, output, qr_out, minutes } => {
            encrypt_file(&input, &output, qr_out.as_deref(), minutes)?;
        }
        Commands::Decrypt { input, output } => {
            decrypt_file(&input, output.as_deref())?;
        }
    }
    Ok(())
}

fn encrypt_file(
    input: &str,
    output: &str,
    qr_out: Option<&str>,
    minutes_valid: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut plaintext = Vec::new();
    File::open(input)?.read_to_end(&mut plaintext)?;

    let now = Utc::now();
    let meta = Metadata {
        original_filename: Path::new(input)
            .file_name().unwrap().to_string_lossy().into(),
        created_at: now,
        decrypt_after: now,
        decrypt_before: now + chrono::Duration::minutes(minutes_valid),
    };

    let blob = EncryptedBlob { meta, data: plaintext };
    let serialized = bincode::serialize(&blob)?;

    let drbg = LocalCtrDrbg::default();
    let mut key_bytes = [0u8; 32];
    drbg.fill_bytes(&mut key_bytes, None)?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    drbg.fill_bytes(&mut nonce_bytes, None)?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES init failed: {:?}", e)))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), serialized.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {:?}", e)))?;

    let mut out = File::create(output)?;
    out.write_all(&nonce_bytes)?;
    out.write_all(&ciphertext)?;

    let png_path = qr_out
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}.png", output));
    let hex_key = hex::encode(&key_bytes);
    let code = QrCode::new(hex_key.as_bytes())?;
    let img = code.render::<Luma<u8>>()
                  .min_dimensions(400, 400)
                  .build();
    img.save(&png_path)?;

    println!("\nEncrypted:   {}", output);
    println!("QR-PNG:      {}", png_path);
    println!("Expires at:  {}", blob.meta.decrypt_before);
    Ok(())
}

fn decrypt_file(
    input: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open(input)?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    f.read_exact(&mut nonce_bytes)?;
    let mut ciphertext = Vec::new();
    f.read_to_end(&mut ciphertext)?;

    for attempt in 1..=3 {
        println!("Enter AES key (attempt {}/3):", attempt);
        io::stdout().flush()?;

        let mut key_str = String::new();
        io::stdin().read_line(&mut key_str)?;
        let key_str = key_str.trim();

        let key_bytes = match parse_key(key_str) {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Invalid key format.");
                if attempt == 3 {
                    fs::remove_file(input)?;
                    return Err("3 failed attempts".into());
                }
                continue;
            }
        };

        let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Key setup failed.");
                if attempt == 3 {
                    fs::remove_file(input)?;
                    return Err("3 failed attempts".into());
                }
                continue;
            }
        };

        let decrypted_blob = match cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref()) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("Decryption failed.");
                if attempt == 3 {
                    fs::remove_file(input)?;
                    return Err("3 failed attempts".into());
                }
                continue;
            }
        };

        let blob: EncryptedBlob = bincode::deserialize(&decrypted_blob)?;

        let now = Utc::now();
        if now < blob.meta.decrypt_after || now > blob.meta.decrypt_before {
            eprintln!("File outside valid time window.");
            fs::remove_file(input)?;
            return Err("Expired or early decryption attempt".into());
        }

        let out_path = if let Some(o) = output {
            PathBuf::from(o)
        } else {
            Path::new(input).parent().unwrap().join(&blob.meta.original_filename)
        };
        File::create(&out_path)?.write_all(&blob.data)?;
        fs::remove_file(input)?;

        println!("Decrypted to: {}", fs::canonicalize(&out_path)?.display());
        return Ok(());
    }

    Ok(())
}

fn parse_key(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hex::decode(s)?)
    } else {
        Ok(base64::decode(s)?)
    }
}
