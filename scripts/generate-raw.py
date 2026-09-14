#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
# Cast at the call site: callers often pass int and pointer arguments to varargs.
for header,name,result,fixed in [('sys/syscall.h','syscall','long',6),('sys/prctl.h','prctl','int',4),('sys/ptrace.h','ptrace','long',3)]:
 p=root/'include/guest'/header
 base=p.read_text().split('/* Fixed-width call')[0] if p.exists() else '#pragma once\n#include_next <'+header+'>\n'
 text=base+'\n/* Fixed-width call packing preserves the types of all supplied arguments. */\n#include <stdint.h>\n'
 target='linux_bash_'+name
 text+=result+' '+target+'(long, '+', '.join(['uint64_t']*fixed)+');\n'
 for count in range(1,fixed+2):
  params=['a'+str(i) for i in range(count)]
  packed=['(long)(a0)']+['(uint64_t)(uintptr_t)(a'+str(i)+')' for i in range(1,count)]+['0']*(fixed+1-count)
  text+='#define LBO_'+name+'_'+str(count)+'('+','.join(params)+') '+target+'('+','.join(packed)+')\n'
 text+='#define LBO_'+name+'_PICK('+','.join('_'+str(i) for i in range(1,fixed+2))+',NAME,...) NAME\n'
 text+='#define '+name+'(...) LBO_'+name+'_PICK(__VA_ARGS__,'+','.join('LBO_'+name+'_'+str(i) for i in range(fixed+1,0,-1))+')(__VA_ARGS__)\n'
 p.write_text(text)
