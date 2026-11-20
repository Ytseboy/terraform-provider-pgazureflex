/-!
# Formal Verification of Terraform Plan Modifiers & Resource Lifecycle Contracts

Models:
1. Terraform Plugin Framework `UseStateForUnknown` and `RequiresReplace` plan modifiers.
   - Proves WHY ordering `[UseStateForUnknown, RequiresReplace]` guarantees zero-diff
     idempotency on omitted `Optional+Computed` attributes while STILL forcing replacement
     on explicit config changes.
   - Proves by universal counterexample WHY the buggy reverse ordering
     `[RequiresReplace, UseStateForUnknown]` spuriously triggers replacement on every re-plan!
2. `pgazureflex_entra_role_mapping` state machine:
   - Proves non-destructive teardown (`Delete` clears the `pgaadauth` security label while
     strictly preserving the underlying PostgreSQL role and its owned objects).
   - Proves in-place `object_id` rotation preserves owned objects and produces an idempotent
     post-apply plan.
-/

namespace PgAzureFlex.TerraformLifecycle

/-- Abstract Terraform attribute value at plan time. -/
inductive AttrVal (α : Type) where
  | null
  | unknown
  | known (v : α)
  deriving DecidableEq, Repr

/-- Plan modifier result for a single attribute. -/
structure PlanOut (α : Type) where
  planVal : AttrVal α
  requiresReplace : Bool
  deriving DecidableEq, Repr

/-- Models `stringplanmodifier.UseStateForUnknown()`. -/
def useStateForUnknown {α : Type} (stateVal : AttrVal α) (cur : PlanOut α) : PlanOut α :=
  match cur.planVal, stateVal with
  | .unknown, .known s => { cur with planVal := .known s }
  | _, _               => cur

/-- Models `stringplanmodifier.RequiresReplace()`. -/
def requiresReplace {α : Type} [DecidableEq α] (stateVal : AttrVal α) (cur : PlanOut α) : PlanOut α :=
  match stateVal, cur.planVal with
  | .known s, .known p =>
    if s == p then cur else { cur with requiresReplace := true }
  | .known _, .unknown =>
    -- Prior state is known, plan value is still unknown -> conservative replace!
    { cur with requiresReplace := true }
  | .known _, .null =>
    { cur with requiresReplace := true }
  | _, _ => cur

/-- Correct pipeline: `[UseStateForUnknown, RequiresReplace]`. -/
def planCorrect {α : Type} [DecidableEq α] (stateVal proposedVal : AttrVal α) : PlanOut α :=
  let init : PlanOut α := { planVal := proposedVal, requiresReplace := false }
  requiresReplace stateVal (useStateForUnknown stateVal init)

/-- Buggy reversed pipeline: `[RequiresReplace, UseStateForUnknown]`. -/
def planReversedBuggy {α : Type} [DecidableEq α] (stateVal proposedVal : AttrVal α) : PlanOut α :=
  let init : PlanOut α := { planVal := proposedVal, requiresReplace := false }
  useStateForUnknown stateVal (requiresReplace stateVal init)

/-- Theorem 1 (Idempotency): With `[UseStateForUnknown, RequiresReplace]`, omitting an
    `Optional+Computed` attribute (`proposedVal = unknown`) when prior state is `known s`
    preserves `known s` AND sets `requiresReplace = false`. -/
theorem planCorrect_omitted_is_idempotent {α : Type} [DecidableEq α] (s : α) :
    planCorrect (.known s) .unknown = { planVal := .known s, requiresReplace := false } := by
  simp [planCorrect, useStateForUnknown, requiresReplace]

/-- Theorem 2 (Replace Soundness): With `[UseStateForUnknown, RequiresReplace]`, explicitly
    changing an immutable attribute from `s` to `c ≠ s` sets `requiresReplace = true`. -/
theorem planCorrect_changed_requires_replace {α : Type} [DecidableEq α] (s c : α) (hne : s ≠ c) :
    planCorrect (.known s) (.known c) = { planVal := .known c, requiresReplace := true } := by
  have hbeq : (s == c) = false := beq_false_of_ne hne
  simp [planCorrect, useStateForUnknown, requiresReplace, hbeq]

/-- Theorem 3 (Unchanged Explicit Value): Passing the same explicit value `s` produces
    zero diff and `requiresReplace = false`. -/
theorem planCorrect_unchanged_no_replace {α : Type} [DecidableEq α] (s : α) :
    planCorrect (.known s) (.known s) = { planVal := .known s, requiresReplace := false } := by
  simp [planCorrect, useStateForUnknown, requiresReplace]

/-- Theorem 4 (Bug Proof): With the reversed ordering `[RequiresReplace, UseStateForUnknown]`,
    omitting ANY `Optional+Computed` attribute with prior state `known s` ALWAYS spuriously
    triggers `requiresReplace = true`! -/
theorem planReversedBuggy_always_spurious_replace {α : Type} [DecidableEq α] (s : α) :
    (planReversedBuggy (.known s) .unknown).requiresReplace = true := by
  simp [planReversedBuggy, useStateForUnknown, requiresReplace]

/-! ### `pgazureflex_entra_role_mapping` Non-Destructive State Machine -/

structure RoleCatalogState where
  roleExists : Bool
  canLogin : Bool
  ownedObjectCount : Nat
  entraLabel : Option String
  deriving DecidableEq, Repr

/-- Applying `pgazureflex_entra_role_mapping` (Create or in-place Update/OID rotation). -/
def applyEntraMapping (st : RoleCatalogState) (newLabel : String) (ensureLogin : Bool) : RoleCatalogState :=
  if st.roleExists then
    { st with
      canLogin := st.canLogin || ensureLogin
      entraLabel := some newLabel }
  else
    st

/-- Destroying `pgazureflex_entra_role_mapping`: executes `SECURITY LABEL FOR "pgaadauth" ON ROLE ... IS NULL`. -/
def destroyEntraMapping (st : RoleCatalogState) : RoleCatalogState :=
  { st with entraLabel := none }

/-- Theorem 5 (Non-Destructive Teardown): Destroying `pgazureflex_entra_role_mapping`
    strictly clears `entraLabel` while NEVER dropping the underlying PostgreSQL role
    and NEVER losing any owned database objects. -/
theorem destroyEntraMapping_preserves_role_and_objects (st : RoleCatalogState) :
    let after := destroyEntraMapping st
    after.entraLabel = none ∧
    after.roleExists = st.roleExists ∧
    after.ownedObjectCount = st.ownedObjectCount := by
  simp [destroyEntraMapping]

/-- Theorem 6 (In-Place OID Rotation Safety): Rotating `object_id` from `lbl1` to `lbl2`
    updates the `pgaadauth` label to `some lbl2` while strictly preserving role existence
    and owned objects. -/
theorem inPlace_oid_rotation_preserves_objects (st : RoleCatalogState) (hEx : st.roleExists = true)
    (lbl1 lbl2 : String) (ensureLogin : Bool) :
    let st1 := applyEntraMapping st lbl1 ensureLogin
    let st2 := applyEntraMapping st1 lbl2 ensureLogin
    st2.entraLabel = some lbl2 ∧
    st2.roleExists = true ∧
    st2.ownedObjectCount = st.ownedObjectCount := by
  simp [applyEntraMapping, hEx]

/-- Theorem 7 (Apply Idempotency): Applying the same `pgazureflex_entra_role_mapping` twice
    is strictly idempotent. -/
theorem applyEntraMapping_idempotent (st : RoleCatalogState) (lbl : String) (ensureLogin : Bool) :
    applyEntraMapping (applyEntraMapping st lbl ensureLogin) lbl ensureLogin =
    applyEntraMapping st lbl ensureLogin := by
  cases h : st.roleExists <;> simp [applyEntraMapping, h, Bool.or_assoc, Bool.or_self]

/-- Theorem 8 (Destroy Idempotency): Destroying an already-destroyed mapping is strictly idempotent. -/
theorem destroyEntraMapping_idempotent (st : RoleCatalogState) :
    destroyEntraMapping (destroyEntraMapping st) = destroyEntraMapping st := by
  simp [destroyEntraMapping]

end PgAzureFlex.TerraformLifecycle
