/-!
# Formal Verification of PostgreSQL Identifier & String Literal Quoting

Models `QuoteIdent` and `QuoteLiteral` from `internal/pgclient/sqlutil.go`.
Proves via an explicit PostgreSQL quoted-token lexer state machine that:
1. Quoted identifiers and literals are always properly delimited.
2. Lexing a quoted identifier/literal NEVER breaks out prematurely (SQL injection impossibility),
   consumes the entire token with empty remainder `[]`, and recovers the exact original characters.
3. Quoting is injective: distinct identifiers/literals never collide.
-/

namespace PgAzureFlex.Quoting

/-- Doubles every occurrence of quote character `q` in `cs`. -/
def escapeChar (q : Char) : List Char → List Char
  | [] => []
  | c :: rest =>
    if c == q then
      q :: q :: escapeChar q rest
    else
      c :: escapeChar q rest

/-- Wraps escaped characters in leading and trailing `q`. -/
def quoteWith (q : Char) (cs : List Char) : List Char :=
  q :: (escapeChar q cs ++ [q])

/-- Models `pgclient.QuoteIdent` (`"..."` with `"` doubled). -/
def quoteIdentChars (cs : List Char) : List Char :=
  quoteWith '"' cs

/-- Models `pgclient.QuoteLiteral` (`'...'` with `'` doubled). -/
def quoteLiteralChars (cs : List Char) : List Char :=
  quoteWith '\'' cs

/-- PostgreSQL quoted-token body lexer (after consuming the opening quote `q`).
    Returns `some (decodedChars, remainingInput)` on a closing unescaped `q`,
    or `none` if EOF is reached before closing. -/
def lexQuotedBody (q : Char) : List Char → Option (List Char × List Char)
  | [] => none
  | c :: rest =>
    if c == q then
      match rest with
      | c2 :: rest2 =>
        if c2 == q then
          -- Escaped doubled quote `qq` -> literal `q`, keep lexing body
          match lexQuotedBody q rest2 with
          | some (decoded, rem) => some (q :: decoded, rem)
          | none => none
        else
          -- Single closing quote followed by remaining tokens
          some ([], c2 :: rest2)
      | [] =>
        -- Single closing quote at end of input
        some ([], [])
    else
      match lexQuotedBody q rest with
      | some (decoded, rem) => some (c :: decoded, rem)
      | none => none

/-- PostgreSQL quoted-token lexer starting from the opening quote `q`. -/
def lexQuoted (q : Char) : List Char → Option (List Char × List Char)
  | [] => none
  | c :: rest =>
    if c == q then lexQuotedBody q rest else none

/-- Core lexer soundness lemma: lexing `escapeChar q cs ++ [q]` never terminates early
    and recovers `(cs, [])` exactly. -/
theorem lexQuotedBody_escape_sound (q : Char) (cs : List Char) :
    lexQuotedBody q (escapeChar q cs ++ [q]) = some (cs, []) := by
  induction cs with
  | nil =>
    simp [escapeChar, lexQuotedBody]
  | cons c rest ih =>
    by_cases h : c = q
    · subst h
      simp [escapeChar, lexQuotedBody, ih]
    · have hne : (c == q) = false := beq_false_of_ne h
      simp only [escapeChar, hne, Bool.false_eq_true, ↓reduceIte, List.cons_append]
      unfold lexQuotedBody
      simp [hne, ih]

/-- General round-trip & zero-breakout theorem for `quoteWith`:
    For ANY character list `cs` (including embedded quotes, semicolons, `--`, etc.),
    the PostgreSQL lexer parses `quoteWith q cs` as a SINGLE token with empty remainder `[]`
    and decodes the exact original character list `cs`. -/
theorem lexQuoted_quoteWith_roundtrip (q : Char) (cs : List Char) :
    lexQuoted q (quoteWith q cs) = some (cs, []) := by
  simp [quoteWith, lexQuoted, lexQuotedBody_escape_sound]

/-- `QuoteIdent` round-trip and SQL-breakout impossibility theorem. -/
theorem lexQuoted_quoteIdent_roundtrip (cs : List Char) :
    lexQuoted '"' (quoteIdentChars cs) = some (cs, []) :=
  lexQuoted_quoteWith_roundtrip '"' cs

/-- `QuoteLiteral` round-trip and SQL-breakout impossibility theorem. -/
theorem lexQuoted_quoteLiteral_roundtrip (cs : List Char) :
    lexQuoted '\'' (quoteLiteralChars cs) = some (cs, []) :=
  lexQuoted_quoteWith_roundtrip '\'' cs

/-- Trailing-context non-breakout theorem: if `quoteWith q cs` is followed by any suffix `tail`
    whose first character is NOT `q` (such as space, comma, `)`, `;`, etc.), the lexer stops
    at the exact closing delimiter and leaves `tail` completely untouched. -/
theorem lexQuotedBody_escape_with_tail (q : Char) (cs : List Char) (t : Char) (tail : List Char) (ht : t ≠ q) :
    lexQuotedBody q (escapeChar q cs ++ (q :: t :: tail)) = some (cs, t :: tail) := by
  induction cs with
  | nil =>
    have hne : (t == q) = false := beq_false_of_ne ht
    simp [escapeChar, lexQuotedBody, hne]
  | cons c rest ih =>
    by_cases h : c = q
    · subst h
      simp [escapeChar, lexQuotedBody, ih]
    · have hne : (c == q) = false := beq_false_of_ne h
      simp only [escapeChar, hne, Bool.false_eq_true, ↓reduceIte, List.cons_append]
      unfold lexQuotedBody
      simp [hne, ih]

theorem lexQuoted_quoteWith_suffix_isolated (q : Char) (cs : List Char) (t : Char) (tail : List Char) (ht : t ≠ q) :
    lexQuoted q (quoteWith q cs ++ (t :: tail)) = some (cs, t :: tail) := by
  have h : quoteWith q cs ++ (t :: tail) = q :: (escapeChar q cs ++ (q :: t :: tail)) := by
    simp [quoteWith, List.append_assoc]
  rw [h]
  simp [lexQuoted, lexQuotedBody_escape_with_tail q cs t tail ht]

/-- Injectivity: distinct character lists always produce distinct quoted tokens. -/
theorem quoteWith_injective (q : Char) {a b : List Char}
    (h : quoteWith q a = quoteWith q b) : a = b := by
  have hlex : lexQuoted q (quoteWith q a) = lexQuoted q (quoteWith q b) := by rw [h]
  rw [lexQuoted_quoteWith_roundtrip, lexQuoted_quoteWith_roundtrip] at hlex
  injection hlex with hpair
  exact (Prod.mk.inj hpair).1

theorem quoteIdent_injective {a b : List Char}
    (h : quoteIdentChars a = quoteIdentChars b) : a = b :=
  quoteWith_injective '"' h

theorem quoteLiteral_injective {a b : List Char}
    (h : quoteLiteralChars a = quoteLiteralChars b) : a = b :=
  quoteWith_injective '\'' h

/-- Length bound: every quoted identifier/literal has at least 2 characters (opening + closing quote). -/
theorem quoteWith_length_ge_two (q : Char) (cs : List Char) :
    (quoteWith q cs).length ≥ 2 := by
  simp [quoteWith]

end PgAzureFlex.Quoting
