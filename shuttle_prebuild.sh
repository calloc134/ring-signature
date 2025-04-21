#!/usr/bin/env bash
set -eux

# パッケージリストを最新化
apt update

# ビルドに必要な開発用パッケージ群をインストール
apt install -y \
  pkg-config \
  nettle-dev \
  clang \
  llvm-dev \
  libssl-dev \
  libpq-dev
