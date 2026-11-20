/-!
# Formal Verification of `azure_pg_admin` `WithRoleMembership` State Preservation

Models `Client.WithRoleMembership` from `internal/pgclient/azure.go` for both
PostgreSQL < 16 and PostgreSQL 16+ (where `pg_auth_members` tracks independent
`admin_option`, `inherit_option`, and `set_option` booleans).

Proves:
1. **Liveness / Authorization**: Inside the critical section, both `setOpt = true`
   and `inheritOpt = true` hold (eliminating PostgreSQL 16 `SQLSTATE 42501: must be able to SET ROLE`).
2. **Exact State Preservation (Zero Privilege Leakage & Zero `ADMIN OPTION` Loss)**:
   For EVERY valid prior `pg_auth_members` state `prior` and EVERY PG version mode `isPG16`,
   running `grantTemp` followed by `revokeTemp` restores `prior` **identically**.
-/

namespace PgAzureFlex.RoleMembership

/-- State of the `(targetRole, currentUser)` row in `pg_auth_members`. -/
structure MembershipState where
  hasRow : Bool
  adminOpt : Bool
  inheritOpt : Bool
  setOpt : Bool
  deriving DecidableEq, Repr

/-- Database catalog invariant: if no row exists in `pg_auth_members`, all options are false.
    On PostgreSQL < 16, `hasRow = true` implies `inheritOpt = true ∧ setOpt = true`. -/
def ValidState (isPG16 : Bool) (s : MembershipState) : Prop :=
  (s.hasRow = false → s.adminOpt = false ∧ s.inheritOpt = false ∧ s.setOpt = false) ∧
  (isPG16 = false → s.hasRow = true → s.inheritOpt = true ∧ s.setOpt = true)

/-- Step 1 of `WithRoleMembership`: conditionally grant temporary membership/options.
    Returns `(newState, didGrant)`. -/
def grantTemp (isPG16 : Bool) (prior : MembershipState) : MembershipState × Bool :=
  if !prior.setOpt || !prior.inheritOpt then
    if isPG16 then
      -- PG 16+: GRANT target TO current WITH SET TRUE, INHERIT TRUE (preserves adminOpt)
      ({ hasRow := true, adminOpt := prior.adminOpt, inheritOpt := true, setOpt := true }, true)
    else
      -- PG < 16: GRANT target TO current
      ({ hasRow := true, adminOpt := prior.adminOpt, inheritOpt := true, setOpt := true }, true)
  else
    (prior, false)

/-- Step 2 (`defer`) of `WithRoleMembership`: revoke ONLY the temporary options or row
    that `grantTemp` added, preserving any pre-existing PG 16+ `ADMIN OPTION` row. -/
def revokeTemp (isPG16 : Bool) (prior cur : MembershipState) (didGrant : Bool) : MembershipState :=
  if !didGrant then
    cur
  else if isPG16 && prior.hasRow then
    -- Only revoke SET OPTION if !prior.setOpt and INHERIT OPTION if !prior.inheritOpt
    { cur with
      setOpt := if !prior.setOpt then false else cur.setOpt
      inheritOpt := if !prior.inheritOpt then false else cur.inheritOpt }
  else
    -- Prior had no row: full REVOKE target FROM current removes the row completely
    { hasRow := false, adminOpt := false, inheritOpt := false, setOpt := false }

/-- Theorem 1 (Authorization Soundness): Inside the critical section of `WithRoleMembership`,
    the caller ALWAYS holds `hasRow = true`, `setOpt = true`, and `inheritOpt = true`. -/
theorem grantTemp_ensures_set_and_inherit (isPG16 : Bool) (prior : MembershipState)
    (hvalid : ValidState isPG16 prior) :
    let (mid, _) := grantTemp isPG16 prior
    mid.hasRow = true ∧ mid.setOpt = true ∧ mid.inheritOpt = true := by
  rcases prior with ⟨hr, ha, hi, hs⟩
  rcases hvalid with ⟨hno, hpre⟩
  cases isPG16 <;> cases hr <;> cases ha <;> cases hi <;> cases hs <;> simp_all [grantTemp]

/-- Theorem 2 (Exact State Preservation / Zero Privilege Leakage):
    For EVERY valid initial `pg_auth_members` state `prior` and EVERY PG version,
    `WithRoleMembership` leaves `pg_auth_members` in the EXACT state `prior` upon exit. -/
theorem withRoleMembership_preserves_state (isPG16 : Bool) (prior : MembershipState)
    (hvalid : ValidState isPG16 prior) :
    let (mid, didGrant) := grantTemp isPG16 prior
    revokeTemp isPG16 prior mid didGrant = prior := by
  rcases prior with ⟨hr, ha, hi, hs⟩
  rcases hvalid with ⟨hno, hpre⟩
  cases isPG16 <;> cases hr <;> cases ha <;> cases hi <;> cases hs <;> simp_all [grantTemp, revokeTemp]

/-- Corollary (PG 16 Creator Row Safety): Specifically when PG 16 auto-created a row with
    `ADMIN OPTION = true`, `INHERIT = false`, `SET = false` (the `CREATEROLE` case),
    `WithRoleMembership` temporarily enables `SET` & `INHERIT` and restores `ADMIN OPTION = true`
    with `SET = false`, `INHERIT = false` afterward. -/
theorem pg16_creator_admin_option_preserved :
    let prior : MembershipState := { hasRow := true, adminOpt := true, inheritOpt := false, setOpt := false }
    let (mid, didGrant) := grantTemp true prior
    mid.setOpt = true ∧ mid.inheritOpt = true ∧ mid.adminOpt = true ∧
    revokeTemp true prior mid didGrant = prior := by
  decide

end PgAzureFlex.RoleMembership
