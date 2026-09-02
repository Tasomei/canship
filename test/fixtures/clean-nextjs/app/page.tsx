'use client'

// Test fixture: correct usage. The client only ever touches the anon key, and
// anything sensitive goes through a server-side endpoint.
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env['NEXT_PUBLIC_SUPABASE_URL']!,
  process.env['NEXT_PUBLIC_SUPABASE_ANON_KEY']!,
)

export default function Page() {
  async function ask() {
    // Correct: calls our own server route, so no secret reaches the browser
    await fetch('/api/chat', { method: 'POST' })
  }

  return <button onClick={ask}>Ask</button>
}
