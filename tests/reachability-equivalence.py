#!/usr/bin/env python3
"""Exhaustively check the compiler optimization's graph predicate on 3 nodes."""
from itertools import product

def original(edges, roots, target, avoid):
    for root in roots:
        if root==avoid:continue
        pending=[root];seen={root}
        while pending:
            node=pending.pop()
            if node==target:return True
            for successor in edges[node]:
                if successor!=avoid and successor not in seen:
                    seen.add(successor);pending.append(successor)
    return False

def union_search(edges,roots,avoid):
    seen=set(roots)-{avoid};pending=list(seen)
    while pending:
        node=pending.pop()
        for successor in edges[node]:
            if successor!=avoid and successor not in seen:
                seen.add(successor);pending.append(successor)
    return seen

checks=0
for bits in product([False,True],repeat=9):
    edges=[[j for j in range(3) if bits[3*i+j]] for i in range(3)]
    for selected in product([False,True],repeat=3):
        roots=[i for i in range(3) if selected[i]]
        for avoid in range(3):
            reachable=union_search(edges,roots,avoid)
            for target in range(3):
                assert original(edges,roots,target,avoid)==(target in reachable)
                checks+=1
print(f'PASS: {checks} graph predicates, including cycles and disconnected blocks')
