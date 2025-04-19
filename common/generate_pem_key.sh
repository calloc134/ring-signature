#!/bin/bash
set -e

# 出力ディレクトリ準備
mkdir -p keys

# 1. Signer 用鍵ペア生成
openssl genpkey -algorithm RSA \
    -out keys/signer_private.pem \
    -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout \
    -in keys/signer_private.pem \
    -out keys/signer_public.pem

# 2. Member1 用鍵ペア生成（公開鍵のみ使用）
openssl genpkey -algorithm RSA \
    -out keys/member1_private.pem \
    -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout \
    -in keys/member1_private.pem \
    -out keys/member1_public.pem

# 3. Member2 用鍵ペア生成（公開鍵のみ使用）
openssl genpkey -algorithm RSA \
    -out keys/member2_private.pem \
    -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout \
    -in keys/member2_private.pem \
    -out keys/member2_public.pem

# 秘密鍵削除
rm -f keys/member1_private.asc
rm -f keys/member2_private.asc

echo "PEM 鍵の生成が完了しました。"
