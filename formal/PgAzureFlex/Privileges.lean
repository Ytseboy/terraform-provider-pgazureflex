/-!
# Formal Verification of PostgreSQL Privilege Normalization & ACL Transitions

Models `NormalizePrivileges` (`internal/pgclient/sqlutil.go`) and declarative
`GRANT` / `REVOKE` set algebra (`internal/provider/resource_grant.go`).

Proves:
1. `normalize_sound`: Normalized privileges are always valid for the target `ObjectType`.
2. `normalize_all_complete`: Expanding `ALL PRIVILEGES` includes every valid privilege for `ot`.
3. `temp_alias_canonical`: `TEMP` and `TEMPORARY` normalize identically on `database`.
4. `normalize_idempotent`: Re-normalizing normalized privileges preserves membership identically.
5. `grantACL_idempotent` & `revokeACL_idempotent`: Repeated grants/revokes are idempotent.
6. `revoke_after_grant_disjoint`: Granting fresh privileges and revoking them restores the prior ACL.
-/

namespace PgAzureFlex.Privileges

inductive ObjectType where
  | database
  | schema
  | table
  | sequence
  | function
  | type
  deriving DecidableEq, Repr

inductive CanonPriv where
  | connect
  | create
  | temporary
  | usage
  | select
  | insert
  | update
  | delete
  | truncate
  | references
  | trigger
  | execute
  deriving DecidableEq, Repr

inductive RawPriv where
  | canon (p : CanonPriv)
  | tempAlias
  | allPrivileges
  deriving DecidableEq, Repr

def validPrivileges : ObjectType → List CanonPriv
  | .database => [.connect, .create, .temporary]
  | .schema   => [.create, .usage]
  | .table    => [.delete, .insert, .references, .select, .trigger, .truncate, .update]
  | .sequence => [.select, .update, .usage]
  | .function => [.execute]
  | .type     => [.usage]

def dedup {α : Type} [DecidableEq α] : List α → List α
  | [] => []
  | x :: xs => if x ∈ xs then dedup xs else x :: dedup xs

theorem mem_dedup {α : Type} [DecidableEq α] (x : α) (xs : List α) :
    x ∈ dedup xs ↔ x ∈ xs := by
  induction xs with
  | nil => simp [dedup]
  | cons y ys ih =>
    by_cases hy : y ∈ ys
    · simp only [dedup, hy, ↓reduceIte, ih, List.mem_cons]
      constructor
      · intro hx; exact Or.inr hx
      · intro hx
        cases hx with
        | inl hxy => subst hxy; exact hy
        | inr hys => exact hys
    · simp [dedup, hy, ih]

def expandRaw (ot : ObjectType) : RawPriv → List CanonPriv
  | .canon p       => if p ∈ validPrivileges ot then [p] else []
  | .tempAlias     => if .temporary ∈ validPrivileges ot then [.temporary] else []
  | .allPrivileges => validPrivileges ot

def normalize (ot : ObjectType) (raw : List RawPriv) : List CanonPriv :=
  dedup (raw.flatMap (expandRaw ot))

/-- Theorem 1 (Soundness): Every privilege returned by `normalize` is valid for `ot`. -/
theorem normalize_sound (ot : ObjectType) (raw : List RawPriv) (p : CanonPriv)
    (hp : p ∈ normalize ot raw) : p ∈ validPrivileges ot := by
  rw [normalize, mem_dedup, List.mem_flatMap] at hp
  rcases hp with ⟨r, _, hpr⟩
  cases r with
  | canon c =>
    simp [expandRaw] at hpr
    rcases hpr with ⟨hval, rfl⟩
    exact hval
  | tempAlias =>
    simp [expandRaw] at hpr
    rcases hpr with ⟨hval, rfl⟩
    exact hval
  | allPrivileges =>
    simpa [expandRaw] using hpr

/-- Theorem 2 (Completeness of `ALL`): `ALL PRIVILEGES` includes every valid privilege for `ot`. -/
theorem normalize_all_complete (ot : ObjectType) (p : CanonPriv)
    (hp : p ∈ validPrivileges ot) : p ∈ normalize ot [.allPrivileges] := by
  rw [normalize, mem_dedup]
  simpa [expandRaw] using hp

/-- Theorem 3 (Alias Equivalence): `TEMP` and `TEMPORARY` normalize identically on `database`. -/
theorem temp_alias_canonical :
    normalize .database [.tempAlias] = normalize .database [.canon .temporary] := by
  decide

/-- Theorem 4 (Idempotency of Normalization): Re-normalizing normalized privileges preserves membership identically. -/
theorem normalize_idempotent (ot : ObjectType) (raw : List RawPriv) (p : CanonPriv) :
    p ∈ normalize ot ((normalize ot raw).map RawPriv.canon) ↔ p ∈ normalize ot raw := by
  constructor
  · intro h
    rw [normalize, mem_dedup, List.mem_flatMap] at h
    rcases h with ⟨r, hr, hpr⟩
    rw [List.mem_map] at hr
    rcases hr with ⟨c, hc, rfl⟩
    simp [expandRaw] at hpr
    rcases hpr with ⟨_, rfl⟩
    exact hc
  · intro h
    have hval := normalize_sound ot raw p h
    rw [normalize, mem_dedup, List.mem_flatMap]
    refine ⟨RawPriv.canon p, List.mem_map_of_mem RawPriv.canon h, ?_⟩
    simp [expandRaw, hval]

/-- Functional ACL representation: set of privileges currently held by a grantee on an object. -/
abbrev ACL := CanonPriv → Bool

def grantACL (acl : ACL) (ps : List CanonPriv) : ACL :=
  fun p => acl p || (p ∈ ps)

def revokeACL (acl : ACL) (ps : List CanonPriv) : ACL :=
  fun p => acl p && !(p ∈ ps)

/-- Theorem 5 (Grant Idempotency): Applying `GRANT ps` twice produces the identical ACL. -/
theorem grantACL_idempotent (acl : ACL) (ps : List CanonPriv) :
    grantACL (grantACL acl ps) ps = grantACL acl ps := by
  funext p
  simp [grantACL, Bool.or_assoc, Bool.or_self]

/-- Theorem 6 (Revoke Idempotency): Applying `REVOKE ps` twice produces the identical ACL. -/
theorem revokeACL_idempotent (acl : ACL) (ps : List CanonPriv) :
    revokeACL (revokeACL acl ps) ps = revokeACL acl ps := by
  funext p
  simp [revokeACL, Bool.and_assoc, Bool.and_self]

/-- Theorem 7 (Clean Teardown): Granting privileges disjoint from the prior ACL and then
    revoking them restores the exact original ACL. -/
theorem revoke_after_grant_disjoint (acl : ACL) (ps : List CanonPriv)
    (hdisj : ∀ p ∈ ps, acl p = false) :
    revokeACL (grantACL acl ps) ps = acl := by
  funext p
  by_cases h : p ∈ ps
  · simp [revokeACL, grantACL, h, hdisj p h]
  · simp [revokeACL, grantACL, h]

/-- Authoritative grant (`authoritative = true` or `privileges = []`):
    revokes every valid privilege for `ot` NOT in `desired`, then grants `desired`. -/
def authoritativeGrantACL (ot : ObjectType) (acl : ACL) (desired : List CanonPriv) : ACL :=
  let toRevoke := (validPrivileges ot).filter (fun p => !(p ∈ desired))
  grantACL (revokeACL acl toRevoke) desired

/-- Theorem 8 (Authoritative PUBLIC Revocation): Setting `desired = []` removes EVERY
    valid privilege for `ot` from the ACL (e.g. `CONNECT`, `TEMPORARY`, `CREATE` from `PUBLIC`). -/
theorem authoritative_empty_revokes_all_valid (ot : ObjectType) (acl : ACL) (p : CanonPriv)
    (hp : p ∈ validPrivileges ot) :
    authoritativeGrantACL ot acl [] p = false := by
  simp [authoritativeGrantACL, grantACL, revokeACL, hp]

/-- Theorem 9 (Authoritative Exactness): For any valid privilege `p ∈ validPrivileges ot`,
    `authoritativeGrantACL ot acl desired p = true` iff `p ∈ desired`. -/
theorem authoritative_exact_on_valid (ot : ObjectType) (acl : ACL) (desired : List CanonPriv)
    (p : CanonPriv) (hp : p ∈ validPrivileges ot) :
    authoritativeGrantACL ot acl desired p = (p ∈ desired) := by
  by_cases hd : p ∈ desired
  · simp [authoritativeGrantACL, grantACL, revokeACL, hp, hd]
  · simp [authoritativeGrantACL, grantACL, revokeACL, hp, hd]

end PgAzureFlex.Privileges
