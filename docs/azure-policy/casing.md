# Casing Behavior in ARM and Azure Policy

This document describes the case-sensitivity rules for Azure Resource Manager
(ARM) resource object fields, tags, and Azure Policy string comparisons, with
links and quotes from official Microsoft documentation.

---

## 1. ARM Object Field Keys (Resource & Property Names)

### Resource and Resource Group Names

Resource names and resource group names are **case-insensitive**.

> **"Resource and resource group names are case-insensitive unless specifically
> noted in the Valid Characters column."**
>
> — [Naming rules and restrictions for Azure resources](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules)

> **"The name of the resource group containing the resource to get. The name is
> case insensitive."**
>
> — [Resources - Get REST API](https://learn.microsoft.com/en-us/rest/api/resources/resources/get)

The casing returned by the API may differ from what was originally submitted.
From the naming rules doc:

> **"When using various APIs to retrieve the name for a resource or resource
> group, the returned value might have different casing than what you originally
> specified for the name."**
>
> — [Naming rules and restrictions for Azure resources](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules)

### JSON Property Names (Resource Properties)

ARM uses .NET's JSON deserialization internally, which performs
**case-insensitive** matching of JSON property names to the resource model. There
is no single doc that states this explicitly, but the behavior is consistent
across the platform:

- Property names in ARM resource JSON payloads (e.g., `properties`,
  `storageProfile`, `osDisk`) follow camelCase convention by default.
- ARM's deserialization treats them case-insensitively
  (`OrdinalIgnoreCase` / .NET `StringComparer.OrdinalIgnoreCase`).
- When reading back from ARM, property keys are returned in the casing defined
  by the resource provider's schema, regardless of what was submitted.

### String Values in Resource Properties

String **values** within resource properties are generally **case-sensitive**
unless the specific property documents otherwise. For example:

- `location` values are normalized **by ARM** before Azure Policy sees them
  (e.g., `East US 2` → `eastus2`). The normalization strips spaces and
  lowercases the value. Azure Policy's `equals` operator does **not** treat
  `"East US 2"` as equal to `"eastus2"` — they are different strings even
  case-insensitively. The doc quote below describes the end-to-end behavior
  (ARM normalization + Policy evaluation together):

  > **"Location fields are normalized to support various formats. For example,
  > `East US 2` is considered equal to `eastus2`."**
  >
  > — [Azure Policy definition structure - Fields](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#fields)

- Resource `type` values (e.g., `Microsoft.Storage/storageAccounts`) are
  case-insensitive.

---

## 2. ARM Tags

Tag **names** (keys) are **case-insensitive** for operations. Tag **values** are
**case-sensitive**.

> **"Tag names are case-insensitive for operations. An operation updates or
> retrieves a tag with a tag name, regardless of the casing. However, the
> resource provider might keep the casing you provide for the tag name. You see
> that casing in cost reports."**
>
> **"Tag values are case-sensitive."**
>
> — [Use tags to organize your Azure resources and management hierarchy](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources)

### Tag Name Constraints

> **"Tag names can't contain these characters: `<`, `>`, `%`, `&`, `\`, `?`, `/`"**
>
> — [Use tags to organize your Azure resources and management hierarchy – Limitations](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources#limitations)

Tag names have a limit of 512 characters (128 for storage accounts). Tag values
have a limit of 256 characters. Tag names can contain Unicode characters (with
the above restrictions), so case-insensitive comparison of tag names must handle
Unicode, not just ASCII.

Note: The exact comparison semantics for tag name matching are
`OrdinalIgnoreCase` (byte-level, ASCII-like folding for A-Z only). Characters
outside the ASCII range are compared byte-for-byte.

---

## 3. Azure Policy String Comparisons

### Condition Operators

Azure Policy's 20 condition operators are listed in the official docs. The key
quote on case sensitivity:

> **"String comparisons are made using `InvariantCultureIgnoreCase`."**
>
> **"When using the `match` and `notMatch` conditions, provide a hashtag (`#`)
> to match a digit, question mark (`?`) for a letter, and a dot (`.`) to match
> any character, and any other character to match that actual character. While
> `match` and `notMatch` are case-sensitive, all other conditions that evaluate
> a `stringValue` are case-insensitive. Case-insensitive alternatives are
> available in `matchInsensitively` and `notMatchInsensitively`."**
>
> — [Azure Policy definition structure – Conditions](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)

### Per-Operator Case Sensitivity Summary

| Operator                  | Case Behavior                        |
|---------------------------|--------------------------------------|
| `equals`                  | Case-insensitive (`InvariantCultureIgnoreCase`) |
| `notEquals`               | Case-insensitive                     |
| `contains`                | Case-insensitive                     |
| `notContains`             | Case-insensitive                     |
| `containsKey`             | Case-insensitive                     |
| `notContainsKey`          | Case-insensitive                     |
| `in`                      | Case-insensitive                     |
| `notIn`                   | Case-insensitive                     |
| `like`                    | Case-insensitive                     |
| `notLike`                 | Case-insensitive                     |
| `greater`                 | Case-insensitive                     |
| `greaterOrEquals`         | Case-insensitive                     |
| `less`                    | Case-insensitive                     |
| `lessOrEquals`            | Case-insensitive                     |
| `exists`                  | N/A (boolean check, not string)      |
| `match`                   | **Case-sensitive**                   |
| `notMatch`                | **Case-sensitive**                   |
| `matchInsensitively`      | Case-insensitive                     |
| `notMatchInsensitively`   | Case-insensitive                     |

### What is `InvariantCultureIgnoreCase`?

In .NET, `StringComparison.InvariantCultureIgnoreCase` uses the invariant
culture's casing rules to perform case-insensitive comparison. On .NET 5+ it
delegates to ICU's collation engine. This differs from `OrdinalIgnoreCase`
(which only folds ASCII A-Z, no string expansion) and from
`CurrentCultureIgnoreCase` (which varies by locale).

Key characteristics:
- **Linguistic comparison** — it is a full collation-based comparison, not a
  simple character mapping. Comparison is done by computing collation weights
  at the primary/secondary level while ignoring the tertiary (case) level.
- **Full case expansion** — `ß` **equals** `ss`, `ﬃ` **equals** `ffi`. This is
  different from `OrdinalIgnoreCase`, which does NOT expand these.
- **Canonical equivalence** — composed and decomposed forms are treated as
  equal (e.g., `é` \[U+00E9\] equals `e` + `◌́` \[U+0065 U+0301\]).
- **Culture-neutral** — uses the invariant culture, not affected by the current
  thread's locale.
- Handles the full Unicode range (not limited to ASCII).

#### Comparison of .NET string comparison modes

| Behavior                   | `Ordinal` | `OrdinalIgnoreCase` | `InvariantCultureIgnoreCase` |
|----------------------------|-----------|---------------------|------------------------------|
| Case folding scope         | None      | ASCII A-Z only      | Full Unicode                 |
| `ß` equals `ss`            | No        | No                  | **Yes**                      |
| `ﬃ` equals `ffi`           | No        | No                  | **Yes**                      |
| `é` (NFC) equals `é` (NFD) | No        | No                  | **Yes**                      |
| `İ` equals `I`             | No        | No                  | **Yes**                      |
| Culture-dependent           | No        | No                  | No (invariant)               |

### Rust Equivalence

There is no single built-in Rust function that matches
`InvariantCultureIgnoreCase`. The options, in increasing accuracy:

| .NET Comparison                 | Closest Rust Equivalent                                | Gap                                |
|---------------------------------|--------------------------------------------------------|------------------------------------|
| `Ordinal` (case-sensitive)      | `str::eq()` / `PartialEq`                             | None                               |
| `OrdinalIgnoreCase`             | `str::eq_ignore_ascii_case()`                          | None                               |
| `InvariantCultureIgnoreCase`    | Unicode Full Case Folding (C+F from `CaseFolding.txt`) | Misses NFC/NFD canonical equivalence |
| `InvariantCultureIgnoreCase`    | Full Case Folding + NFC normalization                  | Near-identical for all practical input |
| `InvariantCultureIgnoreCase`    | ICU4X `icu_collator` crate                             | Exact (same engine as .NET 5+)     |

#### Recommended implementation: Full Case Folding

Full Case Folding uses status C (Common) and F (Full) entries from Unicode's
`CaseFolding.txt`. Unlike Simple Case Folding (status C+S), it handles
**multi-character expansions** (e.g., `ß` → `ss`), matching
`InvariantCultureIgnoreCase` behavior. It can be implemented with zero heap
allocation using a buffered char iterator:

```rust
enum CaseFold {
    One(char),
    Two(char, char),
    Three(char, char, char),
}

fn full_case_fold(c: char) -> CaseFold {
    // ~1,400 entries from Unicode CaseFolding.txt (status C + F)
    // Binary search in a static table
    match CASE_FOLD_TABLE.binary_search_by_key(&c, |entry| entry.from) {
        Ok(i) => CASE_FOLD_TABLE[i].to,
        Err(_) => CaseFold::One(c),
    }
}

/// Zero-allocation iterator that yields the full case fold of each char.
struct FullCaseFoldIter<'a> {
    chars: core::str::Chars<'a>,
    buf: [char; 3],
    pos: u8,
    len: u8,
}

fn ci_equals(a: &str, b: &str) -> bool {
    FullCaseFoldIter::new(a).eq(FullCaseFoldIter::new(b))
}

fn ci_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    FullCaseFoldIter::new(a).cmp(FullCaseFoldIter::new(b))
}
```

This is zero-allocation, `no_std` compatible, and handles the key cases that
differ between `OrdinalIgnoreCase` and `InvariantCultureIgnoreCase` (ß=ss,
ligatures, full Unicode case folding).

The one gap vs true `InvariantCultureIgnoreCase` is **NFC/NFD canonical
equivalence** (e.g., composed `é` vs decomposed `e` + combining accent). For
Azure Policy this gap is negligible — ARM normalizes resource data to a
consistent Unicode form before Policy evaluates it.

#### Note on Rust's `str::to_lowercase()`

Rust's `str::to_lowercase()` uses **full case mapping** (Unicode `SpecialCasing`
+ `UnicodeData`), which is similar in scope to full case folding but not
identical. Key differences:
- `to_lowercase()` is context-sensitive (e.g., final sigma `Σ` → `ς` at word
  end vs `σ` elsewhere). Case folding is context-free.
- `to_lowercase()` allocates a new `String` on every call.
- For practical Azure Policy data, the results are equivalent.

---

## Summary of Comparison Modes

| Context                          | Comparison Mode                          | ASCII-only? | Notes |
|----------------------------------|------------------------------------------|-------------|-------|
| ARM resource/group names         | `OrdinalIgnoreCase`                      | Yes (names are ASCII identifiers) | |
| ARM JSON property keys           | `OrdinalIgnoreCase`                      | Yes (keys are ASCII camelCase) | |
| ARM tag names                    | `OrdinalIgnoreCase`                      | No (Unicode allowed) | |
| ARM tag values                   | Case-sensitive (ordinal)                 | No | |
| Azure Policy `match`/`notMatch`  | Case-sensitive (ordinal)                 | N/A | |
| Azure Policy all other operators | `InvariantCultureIgnoreCase`             | No | Full case expansion (ß=ss), canonical equivalence |
| ARM `location` field             | Normalized **by ARM** (e.g., `East US 2`→`eastus2`) | Yes | Not done by Policy |

---

## References

1. [Naming rules and restrictions for Azure resources](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules)
2. [Use tags to organize your Azure resources and management hierarchy](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources)
3. [Azure Policy definition structure – Policy rule (Conditions)](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions)
4. [Resources - Get REST API](https://learn.microsoft.com/en-us/rest/api/resources/resources/get)
5. [Unicode CaseFolding.txt](https://www.unicode.org/Public/UCD/latest/ucd/CaseFolding.txt)
