// Test fixture: two credentials from different providers on one line.
//
// This is the shape that broke canship's central promise. Redaction used to be
// each rule's job: the OpenAI rule masked the OpenAI key and left the GitHub
// token in full, the GitHub rule did the reverse, and serialising both findings
// put both keys in the output — terminal, JSON, HTML and the prompt meant for
// pasting into an assistant.
//
// Both values are fake but correctly formed. They have to be: a malformed one
// matches no pattern, and the test would pass without proving anything.
export const clients = { openai: 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn', github: 'ghp_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn123' }

// A third format, on its own line. The Supabase secret key was recognised by
// the framework helper from the beginning but never added to the pattern
// table — and that table is what both the hardcoded-secret rule and the
// output-boundary redaction walk. So it went unreported, and beside another
// credential it was printed in full: redaction cannot mask a format nobody
// told it about.
export const supabase = { key: 'sb_secret_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn' }
