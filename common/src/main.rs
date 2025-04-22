use anyhow::Result;
use common::{KeyPair, PublicKey};
use num_traits::One;
// 定数モジュールをインポート
use common::constants::COMMON_DOMAIN_BIT_LENGTH_ADDITION;
// リング署名関連関数をインポート
use common::ring::{ring_sign, ring_verify};
// RSA関連関数と構造体をインポート
use common::rsa::{
    load_keypair_from_pgp, load_public_key_from_pem, load_public_key_from_pgp,
    load_secret_key_from_pem, rsa_sign, rsa_verify,
};
// ハッシュ関数 (SHA3-256)
use sha3::Digest;
// パス操作用
// ログ出力用
use log::{debug, error, info};
// dialoguer をインポート
use dialoguer::{Input, Password, Select};
// textplots をインポート
use num_bigint::ToBigInt;
use num_traits::ToPrimitive; // Import ToPrimitive trait
use num_traits::Zero;
use textplots::{Chart, Plot, Shape}; // Added textplots imports

fn main() -> Result<()> {
    // ロガー初期化
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 鍵ファイル形式を選択
    let formats = &["pem", "asc"];
    let fmt_idx = Select::new()
        .with_prompt("鍵ファイル形式を選択")
        .items(formats)
        .default(0)
        .interact()?;
    let fmt = formats[fmt_idx];

    // 署名者秘密鍵ファイルパス入力
    let signer_priv_path: String = Input::<String>::new()
        .with_prompt("署名者秘密鍵ファイルパス")
        .default(
            match fmt {
                "pem" => "keys/signer_private.pem",
                _ => "keys/signer_private.asc",
            }
            .to_string(),
        )
        .interact_text()?;

    // PEMの場合は公開鍵ファイルパスも入力
    let signer_pub_path = if fmt == "pem" {
        Some(
            Input::<String>::new()
                .with_prompt("署名者公開鍵ファイルパス")
                .default("keys/signer_public.pem".to_string())
                .interact_text()?,
        )
    } else {
        None
    };

    // ASCの場合はパスワード入力
    let password = if fmt == "asc" {
        Some(
            Password::new()
                .with_prompt("秘密鍵パスワード")
                .allow_empty_password(false)
                .interact()?,
        )
    } else {
        None
    };

    // メンバー公開鍵ファイルパス入力
    let member1_pub_path: String = Input::<String>::new()
        .with_prompt("メンバー1 公開鍵ファイルパス")
        .default(
            match fmt {
                "pem" => "keys/member1_public.pem",
                _ => "keys/member1_public.asc",
            }
            .to_string(),
        )
        .interact_text()?;
    let member2_pub_path: String = Input::<String>::new()
        .with_prompt("メンバー2 公開鍵ファイルパス")
        .default(
            match fmt {
                "pem" => "keys/member2_public.pem",
                _ => "keys/member2_public.asc",
            }
            .to_string(),
        )
        .interact_text()?;

    // --- 鍵の読み込み ---
    info!("PGP証明書から鍵を読み込み中...");
    let (signer_public_key, signer_secret_key) = if fmt == "pem" {
        let secret = load_secret_key_from_pem(&signer_priv_path)?;
        let public = load_public_key_from_pem(signer_pub_path.as_ref().unwrap())?;
        (public, secret)
    } else {
        let kp = load_keypair_from_pgp(&signer_priv_path, password.as_deref())?;
        (kp.public.clone(), kp.secret)
    };
    let member1_public_key = if fmt == "pem" {
        load_public_key_from_pem(&member1_pub_path)?
    } else {
        load_public_key_from_pgp(&member1_pub_path)?
    };
    let member2_public_key = if fmt == "pem" {
        load_public_key_from_pem(&member2_pub_path)?
    } else {
        load_public_key_from_pgp(&member2_pub_path)?
    };

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

    // 署名者の公開鍵と秘密鍵のモジュラスが一致するか確認 (任意)
    if signer_public_key.n != signer_secret_key.n {
        error!("エラー: 署名者の公開鍵と秘密鍵のモジュラスが一致しません！");
    }

    info!(
        "署名者のモジュラス n (先頭20文字): {}...",
        &signer_public_key.n.to_string()[..20]
    );

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
    let (ring_sig_verify_result, t_values) = ring_verify(&ring_pubs, &ring_sig, message, b)?; // Capture tuple

    info!("リング署名検証結果: {}", ring_sig_verify_result);

    // --- 検証過程のグラフ描画 ---
    info!("検証過程のグラフを描画中...");
    if let Some(initial_v) = t_values.first() {
        if initial_v.is_zero() {
            info!("初期値vがゼロのため、グラフを描画できません。");
        } else {
            // BigUintをf64に変換（精度に注意）
            // Use .to_bigint().and_then(|bi| bi.to_f64()) for safer conversion
            let initial_v_f64 = initial_v
                .to_bigint()
                .and_then(|bi| bi.to_f64()) // Use ToPrimitive::to_f64
                .unwrap_or(f64::NAN);

            if initial_v_f64.is_nan() || initial_v_f64 == 0.0 {
                info!("初期値vのf64変換に失敗したかゼロのため、グラフを描画できません。");
            } else {
                let points: Vec<(f32, f32)> = t_values
                    .iter()
                    .enumerate()
                    .filter_map(|(i, t)| {
                        // Use .to_bigint().and_then(|bi| bi.to_f64()) for safer conversion
                        let t_f64 = t.to_bigint().and_then(|bi| bi.to_f64()).unwrap_or(f64::NAN); // Use ToPrimitive::to_f64
                        if t_f64.is_nan() {
                            None
                        } else {
                            // 初期値vに対する割合(%)を計算
                            let ratio_percent = (t_f64 / initial_v_f64 * 100.0) as f32;
                            Some((i as f32, ratio_percent))
                        }
                    })
                    .collect();

                if points.is_empty() {
                    info!("グラフ描画用のデータ点がありません。");
                } else {
                    println!("リング署名検証過程 (v={}に対する割合 %):", initial_v);
                    Chart::new(120, 60, 0.0, points.len() as f32 - 1.0)
                        .lineplot(&Shape::Lines(&points))
                        .nice(); // Use nice() to automatically adjust y-axis range
                }
            }
        }
    } else {
        info!("検証過程の値が存在しないため、グラフを描画できません。");
    }

    Ok(())
}
