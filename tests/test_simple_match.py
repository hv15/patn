import pytest

from patn import IndexType, MatchType, Cond, Index, parse_cond, handle_val

def test_create_cond ():
    cond = parse_cond ("M[0]==M[1]", 0)
    assert isinstance (cond, Cond)
    assert isinstance (cond.lhs, Index)
    assert isinstance (cond.rhs, Index)


def test_create_index ():
    index = handle_val ("P[0]:1")
    assert isinstance(index, Index)
    assert index.index == 0
    assert index.type == IndexType.PMatch
    assert index.optype == MatchType.Num
    assert index.opidx == 1
