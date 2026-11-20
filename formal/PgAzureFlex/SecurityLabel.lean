/-!
# Formal Verification of Azure `pgaadauth` Security Label Format & Parse

Models `FormatPGAADAuthSecurityLabel` and `ParsePGAADAuthSecurityLabel` from
`internal/pgclient/azure.go` for `SECURITY LABEL FOR "pgaadauth" ON ROLE`.

Proves:
1. Exact round-trip bijection (`parseTokens (formatTokens l) = some l`) for every valid Entra label.
2. Injectivity: distinct `EntraLabel` configurations never serialize to the same label.
3. Privilege & MFA soundness: `"admin"` appears in the rendered label iff `isAdmin = true`,
   and `"mfa"` appears iff `isMFA = true`.
-/

namespace PgAzureFlex.SecurityLabel

inductive PrincipalType where
  | user
  | group
  | service
  deriving DecidableEq, Repr

def PrincipalType.toChars : PrincipalType → List Char
  | .user => ['u', 's', 'e', 'r']
  | .group => ['g', 'r', 'o', 'u', 'p']
  | .service => ['s', 'e', 'r', 'v', 'i', 'c', 'e']

def PrincipalType.ofChars? : List Char → Option PrincipalType
  | ['u', 's', 'e', 'r'] => some .user
  | ['g', 'r', 'o', 'u', 'p'] => some .group
  | ['s', 'e', 'r', 'v', 'i', 'c', 'e'] => some .service
  | _ => none

theorem PrincipalType.ofChars_toChars (pt : PrincipalType) :
    PrincipalType.ofChars? pt.toChars = some pt := by
  cases pt <;> rfl

structure EntraLabel where
  oid : List Char
  ptype : PrincipalType
  isAdmin : Bool
  isMFA : Bool
  deriving DecidableEq, Repr

/-- An OID is well-formed for `pgaadauth` if it is non-empty (all UUIDs satisfy this). -/
def ValidOID (oid : List Char) : Prop :=
  oid ≠ []

def stripPrefix : List Char → List Char → Option (List Char)
  | [], s => some s
  | p :: ps, c :: cs => if p == c then stripPrefix ps cs else none
  | _ :: _, [] => none

theorem stripPrefix_append (p s : List Char) :
    stripPrefix p (p ++ s) = some s := by
  induction p with
  | nil => rfl
  | cons c cs ih =>
    simp [stripPrefix, ih]

abbrev aadauthTok : List Char := "aadauth".toList
abbrev oidPrefix  : List Char := "oid=".toList
abbrev typePrefix : List Char := "type=".toList
abbrev adminTok   : List Char := "admin".toList
abbrev mfaTok     : List Char := "mfa".toList

/-- Models `FormatPGAADAuthSecurityLabel` as its comma-delimited token list:
    `["aadauth", "oid=<oid>", "type=<ptype>", ...admin, ...mfa]`. -/
def formatTokens (l : EntraLabel) : List (List Char) :=
  [aadauthTok, oidPrefix ++ l.oid, typePrefix ++ l.ptype.toChars]
    ++ (if l.isAdmin then [adminTok] else [])
    ++ (if l.isMFA then [mfaTok] else [])

structure ParseAcc where
  oid : Option (List Char) := none
  ptype : Option PrincipalType := none
  isAdmin : Bool := false
  isMFA : Bool := false

def parseStep (acc : ParseAcc) (tok : List Char) : ParseAcc :=
  match stripPrefix oidPrefix tok with
  | some v => { acc with oid := some v }
  | none =>
    match stripPrefix typePrefix tok with
    | some v => { acc with ptype := PrincipalType.ofChars? v }
    | none =>
      if tok == adminTok then
        { acc with isAdmin := true }
      else if tok == mfaTok then
        { acc with isMFA := true }
      else
        acc

/-- Models `ParsePGAADAuthSecurityLabel` over the comma-split token stream. -/
def parseTokens : List (List Char) → Option EntraLabel
  | t :: rest =>
    if t == aadauthTok then
      let acc := rest.foldl parseStep {}
      match acc.oid, acc.ptype with
      | some oid, some pt =>
        if oid ≠ [] then
          some { oid := oid, ptype := pt, isAdmin := acc.isAdmin, isMFA := acc.isMFA }
        else
          none
      | _, _ => none
    else
      none
  | [] => none

private theorem parseStep_oid (acc : ParseAcc) (oid : List Char) :
    parseStep acc ('o' :: 'i' :: 'd' :: '=' :: oid) = { acc with oid := some oid } := by
  rfl

private theorem parseStep_type (acc : ParseAcc) (pt : PrincipalType) :
    parseStep acc ('t' :: 'y' :: 'p' :: 'e' :: '=' :: pt.toChars) = { acc with ptype := some pt } := by
  cases pt <;> rfl

private theorem parseStep_admin (acc : ParseAcc) :
    parseStep acc ['a', 'd', 'm', 'i', 'n'] = { acc with isAdmin := true } := by
  rfl

private theorem parseStep_mfa (acc : ParseAcc) :
    parseStep acc ['m', 'f', 'a'] = { acc with isMFA := true } := by
  rfl

/-- Main round-trip theorem: formatting ANY valid `EntraLabel` and parsing it back
    recovers the exact original `EntraLabel` (for all `oid`, `ptype`, `isAdmin`, `isMFA`). -/
theorem parse_format_roundtrip (l : EntraLabel) (hoid : ValidOID l.oid) :
    parseTokens (formatTokens l) = some l := by
  cases l with
  | mk oid pt isAdmin isMFA =>
    have hne : oid ≠ [] := hoid
    cases isAdmin <;> cases isMFA <;>
      simp [formatTokens, parseTokens, parseStep_oid, parseStep_type,
            parseStep_admin, parseStep_mfa, hne]

/-- Injectivity: two valid `EntraLabel`s with equal formatted token lists are strictly equal. -/
theorem formatTokens_injective {a b : EntraLabel}
    (ha : ValidOID a.oid) (hb : ValidOID b.oid)
    (h : formatTokens a = formatTokens b) : a = b := by
  have hp : parseTokens (formatTokens a) = parseTokens (formatTokens b) := by rw [h]
  rw [parse_format_roundtrip a ha, parse_format_roundtrip b hb] at hp
  injection hp

/-- Security property: `"admin"` token is present iff `l.isAdmin = true`. -/
theorem admin_token_iff (l : EntraLabel) :
    adminTok ∈ formatTokens l ↔ l.isAdmin = true := by
  cases l with
  | mk oid pt isAdmin isMFA =>
    have h1 : adminTok ≠ aadauthTok := by decide
    have h2 : adminTok ≠ oidPrefix ++ oid := by
      intro heq
      have hsp := congrArg (stripPrefix oidPrefix) heq
      rw [stripPrefix_append] at hsp
      exact absurd hsp (by simp [stripPrefix, oidPrefix, adminTok])
    have h3 : adminTok ≠ typePrefix ++ pt.toChars := by
      cases pt <;> decide
    have h4 : adminTok ≠ mfaTok := by decide
    cases isAdmin <;> cases isMFA <;>
      simp [formatTokens, h1, h2, h3, h4]

/-- Security property: `"mfa"` token is present iff `l.isMFA = true`. -/
theorem mfa_token_iff (l : EntraLabel) :
    mfaTok ∈ formatTokens l ↔ l.isMFA = true := by
  cases l with
  | mk oid pt isAdmin isMFA =>
    have h1 : mfaTok ≠ aadauthTok := by decide
    have h2 : mfaTok ≠ oidPrefix ++ oid := by
      intro heq
      have hsp := congrArg (stripPrefix oidPrefix) heq
      rw [stripPrefix_append] at hsp
      exact absurd hsp (by simp [stripPrefix, oidPrefix, mfaTok])
    have h3 : mfaTok ≠ typePrefix ++ pt.toChars := by
      cases pt <;> decide
    have h4 : mfaTok ≠ adminTok := by decide
    cases isAdmin <;> cases isMFA <;>
      simp [formatTokens, h1, h2, h3, h4]

end PgAzureFlex.SecurityLabel
