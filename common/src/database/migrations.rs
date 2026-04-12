use sqlx::Error;
use tracing::{info, error};
use super::Database;

/// Run database migrations
pub async fn run_migrations(db: &Database) -> Result<(), Error> {
    info!("Running database migrations");
    
    // Run migrations from the common/migrations directory
    sqlx::migrate!("./migrations")
        .run(db.pool())
        .await?;
    
    info!("Database migrations completed successfully");
    Ok(())
}

/// Check if pgvector extension is available
pub async fn check_vector_extension(db: &Database) -> Result<bool, Error> {
    let result = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')"
    )
    .fetch_one(db.pool())
    .await?;
    
    Ok(result)
}

/// Get database version info
pub async fn get_db_version(db: &Database) -> Result<String, Error> {
    let version = sqlx::query_scalar::<_, String>("SELECT version()")
        .fetch_one(db.pool())
        .await?;
    
    Ok(version)
}
