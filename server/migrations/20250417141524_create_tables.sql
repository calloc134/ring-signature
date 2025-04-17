-- 必要な拡張機能 (変更なし)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- テーブル: users
-- Keybaseユーザー情報を格納するテーブル
CREATE TABLE users (
    -- ユーザーの一意なID (内部識別子)
    -- とりあえず動作することを考えUUIDv4を許容
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Keybaseユーザー名 (一意である必要がある)
    keybase_username VARCHAR(255) NOT NULL UNIQUE,

    -- レコード作成日時
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    -- 必要であれば、最終更新日時なども追加できます
    -- updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- インデックス: Keybaseユーザー名によるユーザー検索を高速化
CREATE INDEX idx_users_keybase_username ON users(keybase_username);

-- テーブル: signatures
-- 署名自体の情報を格納
CREATE TABLE signatures (
    -- 署名の一意なID (変更なし)
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- 署名を作成したユーザーのID (usersテーブルへの外部キー)
    -- ユーザーが削除された場合、関連する署名も削除するか、
    -- もしくは削除を禁止するか (RESTRICT or NO ACTION) を検討。
    -- ここではRESTRICT（削除禁止）を仮定します。
    -- アプリケーション要件に応じて ON DELETE SET NULL や ON DELETE CASCADE も検討可能です。
    creator_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- WASMで生成された実際の署名データ (変更なし)
    signature_data TEXT NOT NULL,

    -- レコード作成日時 (変更なし)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- インデックス: 作成者IDによる署名の検索を高速化
-- 元の idx_signatures_creator_username を置き換え
CREATE INDEX idx_signatures_creator_user_id ON signatures(creator_user_id);


-- テーブル: signature_target_users
-- 特定の署名がどのユーザーを対象としているかを管理するテーブル
-- signature と target_user の多対多の関係を表現
CREATE TABLE signature_target_users (
    -- 関連する署名のID (signaturesテーブルへの外部キー)
    -- ON DELETE CASCADE は元のまま。署名が削除されたら、この関連も削除。
    signature_id UUID NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,

    -- 対象となるユーザーのID (usersテーブルへの外部キー)
    -- 元の target_keybase_username を置き換え
    -- 対象ユーザーが削除された場合、この関連レコードも削除する (CASCADE) のが一般的か。
    -- signature自体は残るが、特定のターゲットへの関連がなくなる。
    target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- 複合主キー (signature_id と target_user_id の組み合わせ)
    PRIMARY KEY (signature_id, target_user_id)
);

-- インデックス: 特定のユーザーIDが対象となっている署名の検索を高速化
-- 元の idx_signature_target_usernames_target_username を置き換え
CREATE INDEX idx_signature_target_users_target_user_id ON signature_target_users(target_user_id);
