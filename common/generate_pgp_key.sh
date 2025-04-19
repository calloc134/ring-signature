#!/bin/bash
set -e

# 1. パスフレーズをユーザーに対話的に入力させる
# -s: 入力を非表示
read -s -p "Enter passphrase for new GPG keys: " PASSPHRASE
echo

# 出力ディレクトリ準備
mkdir -p keys

# ランダム文字列（8文字）生成関数
# /dev/urandom から英数字のみを抽出
random_id() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo
}

# 鍵生成＆キーID取得関数
# 引数: Real Name, Email
generate_key() {
  local name="$1"
  local email="$2"
  # パラメータファイル作成
  cat > keyparams <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: ${name}
Name-Email: ${email}
Expire-Date: 0
Passphrase: ${PASSPHRASE}
%commit
EOF
  # 鍵生成（対話なし）
  gpg --batch --generate-key keyparams
  # 鍵ID抽出
  gpg --list-keys --with-colons "${email}" \
    | awk -F: '/^pub/ { print $5; exit }'
}

# --- 1. Signer 用鍵（秘密鍵のみエクスポート） ---
ID_SIGNER=$(generate_key "User_$(random_id)" "$(random_id)@example.com")
gpg --armor --output keys/signer_private.asc \
    --export-secret-keys "${ID_SIGNER}"

# --- 2. Member1 用鍵（公開鍵のみ） ---
ID_M1=$(generate_key "User_$(random_id)" "$(random_id)@example.com")
gpg --armor --output keys/member1_public.asc \
    --export "${ID_M1}"

# --- 3. Member2 用鍵（公開鍵のみ） ---
ID_M2=$(generate_key "User_$(random_id)" "$(random_id)@example.com")
gpg --armor --output keys/member2_public.asc \
    --export "${ID_M2}"


# 鍵パラメータファイル削除
rm -f keyparams

echo "Generated:"
echo "  Signer secret → keys/signer_private.asc (ID=${ID_SIGNER})"
echo "  Member1 pub   → keys/member1_public.asc (ID=${ID_M1})"
echo "  Member2 pub   → keys/member2_public.asc (ID=${ID_M2})"

echo "PGP 鍵の生成が完了しました。"