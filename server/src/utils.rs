use serde::de::Deserializer;
use serde::Deserialize;

/// カンマ区切りの文字列を Vec<String> にパースします。
pub fn comma_separated<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // まず文字列としてデシリアライズ
    let s = String::deserialize(deserializer)?;
    // カンマで分割 → トリム → 空要素を除去 → Vec<String> に変換
    Ok(s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect())
}
