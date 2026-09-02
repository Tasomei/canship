// Test fixture: a connection string with a plaintext password. All values are fake.
//
// The realistic-looking host is a deliberate regression test:
// earlier versions checked the whole connection string for placeholders, so any
// "example" or "test" in the host caused a miss. Placeholder checking now looks
// only at the password, so this one must be caught.
// The inverse case (host is example.com, must NOT be reported) lives in the
// clean fixture.

// Fatal: connection string contains both username and password
export const DATABASE_URL = 'postgresql://admin:sup3rS3cretPw@db.myapp.io:5432/production'

export function connect(): string {
  return DATABASE_URL
}
