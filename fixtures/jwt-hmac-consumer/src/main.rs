//! Isolated real consumer and process-global startup/race acceptance scenarios.
//! Credentials and identities are synthetic and never production inputs.
use jsonwebtoken::{
    crypto::{CryptoProvider, KeyUtils},
    encode,
    errors::ErrorKind,
    Algorithm, EncodingKey, Header,
};
use secure_identity::{
    jwt_hmac::install_default_provider, AuthenticationRequest, Authenticator, IdentityError,
    TokenKind, TokenValidator, TokenValidatorConfig,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Barrier,
};

const SYNTHETIC_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MSwiaXNzIjoicHJvZmlsZS10ZXN0IiwiYXVkIjoiaW50ZXJuYWwtc2VydmljZSIsInJvbGVzIjpbInJlYWRlciJdfQ.cv9IotDluJZC17vnjwddtMLdh2cgVV8PmtbC4yjZWU8";
static FOREIGN_CALLS: AtomicUsize = AtomicUsize::new(0);
static FOREIGN_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| {
        FOREIGN_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(ErrorKind::InvalidAlgorithm.into())
    },
    verifier_factory: |_, _| {
        FOREIGN_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(ErrorKind::InvalidAlgorithm.into())
    },
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        rsa_pub_components_from_public_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        ec_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        ed_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        compute_digest: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    },
};

async fn authenticate(token: &str) -> Result<(), IdentityError> {
    let validator = TokenValidator::new(TokenValidatorConfig {
        issuer: "profile-test".into(),
        audience: "internal-service".into(),
        secret: vec![b'a'; 32],
    });
    let identity = validator
        .authenticate(&AuthenticationRequest {
            token: token.into(),
            token_kind: TokenKind::BearerJwt,
        })
        .await?;
    if identity.roles != vec!["reader"] {
        return Err(IdentityError::InvalidCredentials);
    }
    Ok(())
}

fn own_workers(barrier: Arc<Barrier>) -> Vec<std::thread::JoinHandle<bool>> {
    (0..16)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                install_default_provider().is_ok()
            })
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    match mode.as_str() {
        "all" => {
            let executable = std::env::current_exe()?;
            for mode in [
                "real-jwt",
                "own-race",
                "foreign-first",
                "own-first",
                "competing-race",
                "early-consumer",
            ] {
                if !std::process::Command::new(&executable)
                    .arg(mode)
                    .status()?
                    .success()
                {
                    return Err("isolated startup scenario failed".into());
                }
            }
            println!("All six isolated real consumer/startup scenarios passed");
        }
        "real-jwt" => {
            install_default_provider()?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let claims = serde_json::json!({"sub":"11111111-1111-4111-8111-111111111111","exp":now+3600,"iat":now,"iss":"profile-test","aud":"internal-service","roles":["reader"]});
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&[b'a'; 32]),
            )?;
            authenticate(&token).await?;
        }
        "own-race" => {
            let barrier = Arc::new(Barrier::new(17));
            let workers = own_workers(barrier.clone());
            barrier.wait();
            for worker in workers {
                assert!(worker.join().map_err(|_| "own initialization panicked")?);
            }
            authenticate(SYNTHETIC_TOKEN).await?;
        }
        "foreign-first" => {
            assert!(FOREIGN_PROVIDER.install_default().is_ok());
            assert!(matches!(
                install_default_provider(),
                Err(IdentityError::ProviderUnavailable)
            ));
            assert!(matches!(
                authenticate(SYNTHETIC_TOKEN).await,
                Err(IdentityError::ProviderUnavailable)
            ));
            assert_eq!(FOREIGN_CALLS.load(Ordering::SeqCst), 0);
        }
        "own-first" => {
            install_default_provider()?;
            assert!(FOREIGN_PROVIDER.install_default().is_err());
            authenticate(SYNTHETIC_TOKEN).await?;
            assert_eq!(FOREIGN_CALLS.load(Ordering::SeqCst), 0);
        }
        "competing-race" => {
            let barrier = Arc::new(Barrier::new(18));
            let workers = own_workers(barrier.clone());
            let foreign_barrier = barrier.clone();
            let foreign = std::thread::spawn(move || {
                foreign_barrier.wait();
                FOREIGN_PROVIDER.install_default().is_ok()
            });
            barrier.wait();
            let foreign_won = foreign
                .join()
                .map_err(|_| "foreign initialization panicked")?;
            for worker in workers {
                assert_eq!(
                    worker.join().map_err(|_| "own initialization panicked")?,
                    !foreign_won
                );
            }
            let outcome = authenticate(SYNTHETIC_TOKEN).await;
            if foreign_won {
                assert!(matches!(outcome, Err(IdentityError::ProviderUnavailable)));
            } else {
                outcome?;
            }
            assert_eq!(FOREIGN_CALLS.load(Ordering::SeqCst), 0);
        }
        "early-consumer" => {
            // Deliberately call the upstream API before the required library hook.
            // Capture only that known upstream failure, never an assertion sentinel.
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let early = std::panic::catch_unwind(|| {
                encode(
                    &Header::new(Algorithm::HS256),
                    &serde_json::json!({"exp":4102444800u64}),
                    &EncodingKey::from_secret(&[b'a'; 32]),
                )
            });
            std::panic::set_hook(previous);
            assert!(early.is_err());
            assert!(matches!(
                install_default_provider(),
                Err(IdentityError::ProviderUnavailable)
            ));
            assert!(matches!(
                authenticate(SYNTHETIC_TOKEN).await,
                Err(IdentityError::ProviderUnavailable)
            ));
        }
        _ => return Err("unknown qualification mode".into()),
    }
    Ok(())
}
