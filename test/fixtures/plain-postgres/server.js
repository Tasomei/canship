// 普通后端数据库项目，不使用 Supabase。
import express from 'express'
import pg from 'pg'

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })
const app = express()

app.get('/api/invoices', async (req, res) => {
  const { rows } = await pool.query('select * from invoices where user_id = $1', [req.user.id])
  res.json(rows)
})

app.listen(3000)
