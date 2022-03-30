PATN
====

A recursive pattern matching strip, useful for scanning through structured text
like source code, checking for structure-level patterns.

Guide
-----

With PATN you can define expressions to match against _structures_ within the text
and then apply a conditional to it.

### Expressions

Simply, expressions are REGEX (PCRE-like, _a la_ Python) where you set out a simple matche or
specify match group(s). The expressions are evaluated per-line of input text and are applied multiple
times (currently there is no facilities to check across lines).

### Conditionals

When performing a match, you can define the following conditions:

| Operation                  | Alt  | Notes                                                                                                                              |
|----------------------------|------|------------------------------------------------------------------------------------------------------------------------------------|
| `skip`                     | `>>` | apply only the expression (and store results for next expression)                                                                  |
| `count`                    | `#`  | Print out number of successful applications of expression (**WIP**)                                                                |
| `M[idx]==/!=M[idx]`        |      | For the current expression (which contains match groups), check equality of one group to another group                             |
| `M[idx]==/!='string'`      |      | For the current expression (which contains match groups), check equality of one group to a string                                  |
| `M[idx]==/!=P[idx]`        |      | For the current expression (which contains match groups), check equality of one group to the result of the previous expression     |
| `<num or range>:M[idx]...` |      | For the current expression, set a constraint on which successful applications of the expression the condition should be applied to |

For `M` and `P` there are also control expressions that set out, given a collection of matches, if the conditional should apply to all, any, or one (this is still **WIP**).

License
-------

This work is released under the ISC License.
