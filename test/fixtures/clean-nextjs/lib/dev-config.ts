// Test fixture: connection strings that are perfectly well formed but point at
// nothing useful. None of them should be reported.
//
// These target RFC-reserved example domains or local addresses, so they are
// worthless to an attacker. Reporting them is pure noise — and noise is what
// makes users stop trusting the tool.

/** Local development database */
export const LOCAL_DB = 'postgresql://postgres:devpassword@localhost:5432/app_dev'

/** The connection string every tutorial uses */
export const DOC_EXAMPLE = 'mongodb://admin:hunter2@db.example.com:27017/mydb'

/** A docker compose service name */
export const DOCKER_REDIS = 'redis://default:localdev@host.docker.internal:6379'
