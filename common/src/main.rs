use anyhow::Result;
use num_traits::One;
// 定数モジュールをインポート
use ring_signature::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION;
// リング署名関連関数をインポート
use ring_signature::ring::{ring_sign, ring_verify};
// RSA関連関数と構造体をインポート
use ring_signature::rsa::{load_public_key_from_pem, load_secret_key_from_pem, KeyPair, PublicKey};
use ring_signature::rsa::{rsa_sign, rsa_verify};
// ハッシュ関数 (SHA3-256)
use sha3::Digest;
// パス操作用
use std::path::Path;
// ログ出力用
use log::{debug, error, info};

fn main() -> Result<()> {
    // ロガー初期化
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 鍵ファイルが格納されているディレクトリのパス設定
    let key_dir = Path::new("keys");
    // 各鍵ファイルのパス設定 (.asc PGP 鍵を読み込み)
    let signer_priv_key_path = key_dir.join("signer_private.asc"); // PGP秘密鍵
    let signer_pub_key_path = key_dir.join("signer_public.asc"); // PGP公開鍵
    let member1_pub_key_path = key_dir.join("member1_public.asc");
    let member2_pub_key_path = key_dir.join("member2_public.asc");

    // --- 鍵の読み込み ---
    info!("PGP鍵ファイルから鍵を読み込み中...");
    // PGP鍵ブロックは load_* 関数内で検出して処理される
    let signer_secret_key = load_secret_key_from_pem(signer_priv_key_path.to_str().unwrap())?;
    // 署名者の公開鍵を読み込み
    let signer_public_key = load_public_key_from_pem(signer_pub_key_path.to_str().unwrap())?;

    // 他のリングメンバーの公開鍵を読み込み
    let member1_public_key = load_public_key_from_pem(member1_pub_key_path.to_str().unwrap())?;
    let member2_public_key = load_public_key_from_pem(member2_pub_key_path.to_str().unwrap())?;

    // リングメンバーの公開鍵リストを作成 (署名者の公開鍵を含む)
    let ring_pubs: Vec<PublicKey> = vec![
        signer_public_key.clone(), // 署名者はインデックス 0
        member1_public_key,
        member2_public_key,
    ];
    // 署名者のインデックスを設定
    let signer_index = 0;

    info!("鍵の読み込み完了。");
    // 読み込んだ鍵情報の一部を表示 (デバッグ用)
    info!(
        "署名者の公開鍵 n (先頭20文字): {}...",
        &signer_public_key.n.to_string()[..20]
    );
    info!(
        "署名者の秘密鍵 n (先頭20文字): {}...",
        &signer_secret_key.n.to_string()[..20]
    );

    // 署名者の公開鍵と秘密鍵のモジュラスが一致するか確認 (任意)
    if signer_public_key.n != signer_secret_key.n {
        error!("エラー: 署名者の公開鍵と秘密鍵のモジュラスが一致しません！");
        // return Err(anyhow::anyhow!("Signer key mismatch"));
    }

    // 署名対象のメッセージ
    let message = b"Hello RSA and Ring Signature!";

    info!("メッセージ: {}", String::from_utf8_lossy(message));

    // --- 通常のRSA署名と検証 (比較用) ---
    info!("RSAでメッセージに署名中...");
    // RSA署名用の共通ドメインビット長 b を計算
    let rsa_b = signer_public_key.n.bits() as usize + COMMON_DOMAIN_BIT_LENGTH_ADDITION;
    // メッセージのハッシュ値を計算
    let hash = sha3::Sha3_256::digest(message);
    // ハッシュ値を BigUint に変換し、2^b で剰余を取る
    let m = num_bigint::BigUint::from_bytes_be(&hash) % (num_bigint::BigUint::one() << rsa_b);

    // 署名者の鍵ペアを作成
    let signer_keypair = KeyPair {
        public: signer_public_key.clone(),
        secret: signer_secret_key.clone(),
    };
    // RSA署名を生成
    let rsa_signature = rsa_sign(&signer_keypair, &m, rsa_b)?;
    // RSA署名を16進数で表示
    info!(
        "RSA署名 (hex): {}",
        rsa_signature
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    info!("RSA署名を検証中...");
    // RSA署名を検証
    let rsa_verify_result = rsa_verify(&signer_public_key, &m, &rsa_signature, rsa_b)?;
    info!("通常RSA署名検証結果: {}", rsa_verify_result);

    // --- リング署名の生成と検証 ---
    // リング署名用の共通ドメインビット長 b を計算 (リング内の最大鍵長を使用)
    let b = ring_pubs
        .iter()
        .map(|pk| pk.n.bits())
        .max()
        .unwrap_or(0) as usize // リングが空の場合のフォールバック (ここでは発生しない想定)
        + COMMON_DOMAIN_BIT_LENGTH_ADDITION;

    // b の計算に失敗した場合のエラーハンドリング
    if b == COMMON_DOMAIN_BIT_LENGTH_ADDITION {
        error!("エラー: 読み込んだ鍵から最大鍵サイズを決定できませんでした。");
        return Err(anyhow::anyhow!("Failed to calculate b"));
    }

    info!("リング署名を生成中...");
    // リング署名を生成
    let ring_sig = ring_sign(
        &ring_pubs,
        signer_index,       // 署名者のインデックス
        &signer_secret_key, // 署名者の秘密鍵
        message,
        b,
    )?;
    // リング署名のグルー値 v を16進数で表示
    info!(
        "リング署名 グルー値 v (hex): {}",
        ring_sig
            .v
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    // デバッグレベルで寄与値 xs を表示 (非常に長くなる可能性があるため)
    debug!(
        "リング署名 寄与値 xs: {:?}",
        ring_sig
            .xs
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
    );

    info!("リング署名を検証中...");
    // リング署名を検証
    let ring_sig_verify_result = ring_verify(&ring_pubs, &ring_sig, message, b)?;

    info!("リング署名検証結果: {}", ring_sig_verify_result);
    Ok(())
}
