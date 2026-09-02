'use client'

// Test fixture: a secret deliberately hardcoded into a client component.
// All values are fake.
import { useState } from 'react'

// Fatal: an OpenAI key written straight into client-side code
const OPENAI_KEY = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'

export default function Page() {
  const [answer, setAnswer] = useState('')

  async function ask() {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENAI_KEY}` },
      body: JSON.stringify({ model: 'gpt-4', messages: [] }),
    })
    setAnswer(JSON.stringify(await res.json()))
  }

  return (
    <button onClick={ask}>{answer || 'Ask'}</button>
  )
}
