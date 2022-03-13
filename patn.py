#!/usr/bin/python3
"""
The patn script takes in a sequence of patterns and conditions,
applies these to some input (via stdin or file), and resolves
each condition for its pattern.

On ever pattern we store the match, which can be accessed in the next
sequence of pattern-conds.

If a pattern fails, the script aborts.

If a condition fails, the script aborts.

Support condition statements:
    -> M[n] ==/!= 'string'
      compare current match to some string
    -> M[n] ==/!= M[n]
      compare current matches
    -> M[n] ==/!= P[n]
      compare the current match with a previous match
    -> >> 'OR' skip
      perform only the pattern match (and use its result
      in the next pattern-cond sequence)
"""
import sys
import re
import enum
import argparse
import copy
import tempfile
from typing import Type, Match, IO, TextIO, Optional, Union, List, Tuple, Sequence

__version__ = "0.1"

IndexType = enum.Enum ('IndexType', 'Match PMatch')
CondType = enum.Enum ('CondType', 'Eq Ne Skip Err')
MatchType = enum.Enum ('MatchType', 'Any All Num NA')

class String ():
    def __init__ (self, value: str) -> None:
        self._value = value

    def __str__ (self) -> str:
        return f"String(value=\"{self._value}\")"

    def __repr__ (self) -> str:
        return self.__str__ ()

    @property
    def value (self) -> str:
        return self._value

class Index ():
    def __init__ (self, ttype: IndexType, index: int, optype: MatchType = MatchType.NA, opidx: int = -1) -> None:
        self._ttype = ttype
        self._index = index
        self._opidx = opidx
        self._optype = optype

    def __str__ (self) -> str:
        if self._optype != MatchType.NA:
            return f"Index(type={self._ttype}, index={self._index}, optype={self._optype}, opidx={self._opidx})"
        else:
            return f"Index(type={self._ttype}, index={self._index})"

    def __repr__ (self) -> str:
        return self.__str__ ()

    @property
    def type (self) -> IndexType:
        return self._ttype

    @property
    def index (self) -> int:
        return self._index

    @property
    def optype (self) -> MatchType:
        return self._optype

    @property
    def opidx (self) -> int:
        return self._opidx

class Cond ():
    def __init__ (self, ctype: CondType, lhs: Optional[Index | String], rhs: Optional[Index | String]) -> None:
        self._ctype = ctype
        self._lhs = lhs
        self._rhs = rhs

    def __str__ (self) -> str:
        if self._ctype != CondType.Skip:
            return f"Cond (type={self._ctype}, lhs={self._lhs}, rhs={self._rhs})"
        else:
            return f"Cond (type={self._ctype})"

    def __repr__ (self) -> str:
        return self.__str__ ()

    @property
    def type (self) -> CondType:
        return self._ctype

    @property
    def lhs (self) -> Optional[Index | String]:
        return self._lhs

    @property
    def rhs (self) -> Optional[Index | String]:
        return self._rhs

class PtnSeq (argparse._AppendAction):
    """
    Class defines the argument sequence for pattern-cond group argparse
    """
    def __call__ (self, parser, namespace, values, option_string):
        grp = { "pattern": values[0], "cond": values[1] }
        return super().__call__ (parser, namespace, grp, option_string)

def die (msg):
    print (msg, file=sys.stderr)
    sys.exit (3)

def fatal (msg) -> None:
    die (f"fatal: {msg}")

def error (msg):
    print (f"error: {msg}", file=sys.stderr)

def warning (msg):
    print (f"warning: {msg}", file=sys.stderr)

def info (msg):
    print (f"info: {msg}")

def handle_val (token: str) -> Index | String:
    if token.startswith ("M"):
        return Index (IndexType.Match, int (token.strip ("M\[\]")))
    elif token.startswith ("P"):
        pidx: int = -1
        mpidx = re.search (r'^P\[(\d+)\]', token)
        if isinstance (mpidx, Match):
            pidx = int (mpidx.group (1))
        else:
            fatal ("Regex for P index failed!")
        pmat = re.search (r'\:(\d+|\&\&|\|\|)$', token)

        idx: int = -1
        pmattype: MatchType = MatchType.NA

        if pmat and pmat.group (1) == '&&':
            pmattype = MatchType.All
        elif pmat and pmat.group (1) == '||':
            pmattype = MatchType.Any
        elif pmat:
            pmattype = MatchType.Num
            idx = int (pmat.group (1))
        else:
            pmattype = MatchType.Any

        return Index (IndexType.PMatch, pidx, pmattype, idx)
    else:
        return String (token.strip ("\"'"))

def handle_cond (lhs: str, opt: str, rhs: str) -> Cond:
    nlhs = handle_val (lhs)
    nrhs = handle_val (rhs)
    ctype: CondType = CondType.Err
    if opt == "==":
        ctype = CondType.Eq
    elif opt == "!=":
        ctype = CondType.Ne
    else:
        fatal (f"Unknown conditional operations: {opt}")

    return Cond (ctype, nlhs, nrhs)

def parse_cond (cond: str, c: int) -> Cond: # type: ignore[return]
    # FIXME 'string opt string' is possible
    rstatm = re.compile ('^\s*(?:skip|(?:[PM]\[\d+\](?:\:\d+|\:&&|\:\|\|){0,1}|["\']\w*["\'])\s*[\!=->][=>]\s*(?:[PM]\[\d+\](?:\:\d+|\:&&|\:\|\|){0,1}|["\']\w*["\']))\s*$')
    rtokens = re.compile ('[PM]\[\d+\](?:\:\d+|\:&&|\:\|\|){0,1}|[\!=]=|>>|skip|["\']\w*["\']')
    rids = re.compile('[MP]\[\d+\]')

    if not re.fullmatch (rstatm, cond):
        fatal (f"Condtional {c} uses incorrect syntax!")

    toks = re.findall(rtokens, cond)
    if toks:
        if toks[0] in ['>>','skip']:
            return Cond (CondType.Skip, None, None)
        elif len (toks) == 3:
            return handle_cond (toks[0], toks[1], toks[2])
        else:
            fatal (f"Conditional {c} is malformed!")
    else:
        fatal (f"Condition \"{cond}\" is invalid!")

def eval_id (ids: Index | String, smatch: Sequence[str], prev: list) -> tuple[list, MatchType, int]: # type: ignore[return]
    if isinstance (ids, Index):
        if ids.optype == MatchType.NA:
            return ([smatch[ids.index]], MatchType.NA, 0)
        else:
            # XXX is it always the case that a match only returns 1 tuple or 1 string?
            try:
                sp = [i[0][ids.index] for i in prev]
                return (sp, ids.optype, ids.opidx)
            except IndexError as e:
                fatal (f"for P[{ids.index}] -> {e}")
    elif isinstance (ids, String):
        return ([ids.value], MatchType.NA, 0)

def eval_cond (cond: Cond, result: list, prev: list) -> bool:
    if cond.type != CondType.Skip:
        for smatch in result:
            # the smatch may be a tuple (when using multigroup regexes)
            # **or** a single string value
            wrp = smatch if isinstance (smatch, tuple) else [smatch]
            if isinstance (cond.lhs, Index | String):
                lhs = eval_id (cond.lhs, wrp, prev)
            else:
                fatal ("No LHS of conditional!")
            if isinstance (cond.rhs, Index | String):
                rhs = eval_id (cond.rhs, wrp, prev)
            else:
                fatal ("No RHS of conditional!")

            res = False
            tmp = []
            if cond.type == CondType.Eq:
                for l in lhs[0]:
                    for r in rhs[0]:
                        tmp.append (l == r)
            elif cond.type == CondType.Ne:
                for l in lhs[0]:
                    for r in rhs[0]:
                        tmp.append (l != r)
            else:
                fatal ("Unknown conditional operation!")

            if all (i == MatchType.NA for i in [lhs[1],rhs[1]]):
                res = all (tmp)
            if any (i == MatchType.Any for i in [lhs[1],rhs[1]]):
                res = any (tmp)
            if any (i == MatchType.All for i in [lhs[1],rhs[1]]):
                res = all (tmp)
            if any (i == MatchType.Num for i in [lhs[1],rhs[1]]):
                s = sum ((lhs[2], rhs[2]))
                if s > len (tmp):
                    fatal ("Expected pattern matches out-of-bound!")
                res = tmp.count (True) == s
            if not res:
                if cond.type == CondType.Eq:
                    error (f"Condition \"{lhs[0]} == {rhs[0]}\" of \"{smatch}\" failed!")
                elif cond.type == CondType.Ne:
                    error (f"Condition \"{lhs[0]} != {rhs[0]}\" of \"{smatch}\" failed!")
            return res

    # only on 'skip'
    return True

def copy_to_tempfile (file: TextIO) -> IO[str]:
    tp = tempfile.TemporaryFile ('w+')
    for l in file:
        tp.write (l)
    tp.seek (0)
    return tp

if __name__ == '__main__':
    parser = argparse.ArgumentParser (prog='patn', description="For a given input, "
               "sequencially find the passed in patterns and check "
               "against each condition that the pattern hold.")
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument ('-e', required=True, nargs=2, action=PtnSeq, metavar=("PATTERN", "COND"))
    parser.add_argument('file', nargs='?', type=argparse.FileType('r'), default=sys.stdin)

    args = parser.parse_args ()

    # parse all conditionals
    patcons: List[Tuple[str, Cond]] = []
    for count, pc in enumerate (args.e, start=1):
        s: Tuple[str, Cond] = (pc['pattern'], parse_cond (pc['cond'], count))
        patcons.append (s)

    # copy content to temp file
    tp = copy_to_tempfile (args.file)
    args.file.close ()

    prev: List[list] = []
    for p, c in patcons:
        found: bool = False
        failed: bool = False
        matches: List[list] = []
        reg = re.compile (p)
        for line in tp:
            res = re.findall (reg, line)
            if res:
                found = True
                matches.append (res)
                print (c)
                if not eval_cond (c, res, prev):
                    error (f"Condition failed for pattern: \"{p}\"!")
                    failed = True
            else:
                continue
        if not found:
            error (f"Pattern: \"{p}\" could not be found!")
        if failed:
            error ("Halting further processing!")
            break
        if prev:
            prev.clear ()
        prev = matches
        tp.seek (0)

    tp.close ()
