'use client'

// 故意将模拟凭据写入客户端组件。
import { useState } from 'react'

// 模拟客户端硬编码密钥。
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
