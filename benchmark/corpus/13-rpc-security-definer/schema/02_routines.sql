-- Project 13, part 2 of 2: the routines, which are the way in.
--
-- SECURITY DEFINER means "run this function as its OWNER". The owner here is
-- postgres, who owns every table in 01_tables.sql, and row-level security does
-- not apply to a table's owner. So a SECURITY DEFINER function is not a
-- convenience wrapper around a protected table — it is a hole through it, and
-- the size of the hole is whatever the function body selects.
--
-- FIRST, the thing that makes any of this measurable: PostgreSQL grants
-- EXECUTE on a new function to PUBLIC by default. Without the REVOKE below,
-- every routine in this file would be callable by anon whatever the GRANTs at
-- the bottom said, and the "revoked" control would not be a control. This is
-- the single most common way a routine ends up callable by a stranger without
-- anybody having granted anything.

-- ---------------------------------------------------------------------------
-- 1. The classic. The table is locked; the function is not.
--
-- Named so that no wordlist would carry it. Routine discovery on this target
-- has to be more than dictionary guessing, or this function is never found and
-- the 20 customer rows behind it are never reported.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.zephyr_customer_export_v2()
RETURNS SETOF public.customers
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT * FROM public.customers ORDER BY id;
$$;

-- ---------------------------------------------------------------------------
-- 2. The injectable one.
--
-- format() with %s instead of %L. %L quotes and escapes its argument as a
-- literal; %s pastes it in. The difference is the whole vulnerability, and it
-- is one character in the source.
--
-- Declared STABLE ON PURPOSE. PL/pgSQL refuses to execute INSERT, UPDATE,
-- DELETE or DDL from a non-VOLATILE function, so this routine can be used to
-- READ anything in the database and cannot be used to change or destroy
-- anything. That guard is asserted in the answer key, not assumed: the key
-- sends a payload containing a DELETE and records what comes back. A fixture
-- that can be dropped by anyone who reads its README is a fixture that gets
-- dropped.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.search_customers(term text)
RETURNS TABLE(id bigint, full_name text, email text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN QUERY EXECUTE format(
    'SELECT id, full_name, email FROM public.customers WHERE full_name ILIKE ''%%%s%%'' ORDER BY id',
    term);
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. The precision control. Same body, same table, SECURITY INVOKER.
--
-- It runs as `anon`, so RLS applies and the policy matches nothing. It is a
-- routine that anon can call and that is NOT a way in. A scanner that reports
-- every callable routine is wrong about this one.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.customers_for_current_user()
RETURNS SETOF public.customers
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT * FROM public.customers ORDER BY id;
$$;

-- ---------------------------------------------------------------------------
-- 4. The second precision control: a SECURITY DEFINER routine that is
-- deliberately safe. It reads locked tables and returns only aggregates, which
-- is exactly what SECURITY DEFINER is FOR. "Definer" is not a synonym for
-- "finding".
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.public_status_counts()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT jsonb_build_object(
    'customers',    (SELECT count(*) FROM public.customers),
    'active_keys',  (SELECT count(*) FROM public.api_keys),
    'events_today', (SELECT count(*) FROM public.audit_events)
  );
$$;

-- ---------------------------------------------------------------------------
-- 5. The WRITE. SECURITY DEFINER, VOLATILE, and it inserts into a table anon
-- holds no privilege on whatsoever.
--
-- It returns the row it wrote, read back OUT of the table, so the HTTP
-- response is itself evidence the insert landed rather than a claim that it
-- did.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.record_contact_request(contact_email text, note text)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  new_id bigint;
  stored text;
BEGIN
  INSERT INTO public.audit_events (actor, action, detail)
  VALUES (contact_email, 'contact_request', note)
  RETURNING id INTO new_id;
  SELECT detail INTO stored FROM public.audit_events WHERE id = new_id;
  RETURN jsonb_build_object('inserted_id', new_id, 'stored_detail', stored);
END;
$$;

-- ---------------------------------------------------------------------------
-- 6. Exists, is in the schema cache, and anon may not call it. The second name
-- no wordlist carries.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.mnemosyne_key_rotation_audit()
RETURNS SETOF public.api_keys
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT * FROM public.api_keys ORDER BY id;
$$;

-- ---------------------------------------------------------------------------
-- Privileges. The REVOKE is not optional; see the header.
-- ---------------------------------------------------------------------------
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated;

GRANT EXECUTE ON FUNCTION public.zephyr_customer_export_v2()               TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.search_customers(text)                    TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.customers_for_current_user()              TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.public_status_counts()                    TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_contact_request(text, text)        TO anon, authenticated;
-- mnemosyne_key_rotation_audit: intentionally nothing.

-- The sequence behind audit_events. record_contact_request runs as postgres,
-- who owns it, so this is not needed for the RPC to work; it is here only so
-- that the absence of a direct-write path is a statement about the TABLE grant
-- and not an accident of sequence privileges.
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;
