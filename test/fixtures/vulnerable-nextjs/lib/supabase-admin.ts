// Test fixture: the shape every Supabase tutorial teaches — one module holding
// the service_role client, imported wherever it is needed.
//
// It exists here to prove two things. First, that the rule follows the import:
// a check that only looked inside route files would miss nearly every real
// project. Second, that the type argument does not hide the constructor —
// createClient<Database>() is the form Supabase's own documentation recommends,
// and a real repository was under-reported because of it.
import { createClient } from '@supabase/supabase-js'
import type { Database } from './database.types'

export const supabaseAdmin = createClient<Database>(
  process.env['SUPABASE_URL']!,
  process.env['SUPABASE_SERVICE_ROLE_KEY']!,
  { auth: { persistSession: false } },
)
