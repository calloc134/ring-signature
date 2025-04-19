use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateSignatureRequest {
    pub v: String,
    pub xs: Vec<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SignatureRecord {
    pub id: Uuid,
    pub v: String,
    pub xs: Vec<String>,
    pub members: Vec<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_signature(
    pool: &PgPool,
    req: CreateSignatureRequest,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query!(
        r#"INSERT INTO signatures (v) VALUES ($1) RETURNING id"#,
        req.v,
    )
    .fetch_one(&mut tx)
    .await?;
    let sig_id = row.id;
    for (idx, (user, x)) in req.members.iter().zip(req.xs.iter()).enumerate() {
        sqlx::query!(
            r#"INSERT INTO signature_members (signature_id, position, member_username, x_value) VALUES ($1, $2, $3, $4)"#,
            sig_id,
            idx as i32,
            user,
            x,
        )
        .execute(&mut tx)
        .await?;
    }
    tx.commit().await?;
    Ok(sig_id)
}

pub async fn get_signatures_for_user(
    pool: &PgPool,
    username: &str,
) -> Result<Vec<SignatureRecord>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT s.id, s.v, s.created_at, sm.position, sm.member_username, sm.x_value
        FROM signatures s
        JOIN signature_members sm ON s.id = sm.signature_id
        WHERE s.id IN (
            SELECT signature_id FROM signature_members WHERE member_username = $1
        )
        ORDER BY s.created_at, sm.position
        "#,
        username,
    )
    .fetch_all(pool)
    .await?;

    let mut records = Vec::new();
    let mut current_id = None;
    let mut current: Option<SignatureRecord> = None;
    for row in rows {
        if Some(row.id) != current_id {
            if let Some(rec) = current.take() {
                records.push(rec);
            }
            current_id = Some(row.id);
            current = Some(SignatureRecord {
                id: row.id,
                v: row.v,
                xs: Vec::new(),
                members: Vec::new(),
                created_at: row.created_at,
            });
        }
        if let Some(ref mut rec) = current {
            rec.members.push(row.member_username);
            rec.xs.push(row.x_value);
        }
    }
    if let Some(rec) = current {
        records.push(rec);
    }
    Ok(records)
}
