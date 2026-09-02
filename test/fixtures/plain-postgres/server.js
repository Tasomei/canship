// Test fixture: an ordinary API server. No Supabase anywhere in this project.
import express from 'express'
import pg from 'pg'

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })
const app = express()

app.get('/api/invoices', async (req, res) => {
  const { rows } = await pool.query('select * from invoices where user_id = $1', [req.user.id])
  res.json(rows)
})

app.listen(3000)
