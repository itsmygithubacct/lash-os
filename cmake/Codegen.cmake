# Keep large generated functions tractable and pointer spills in separate slots.
# Expand late aggregate copies before they can become unresolved memcpy calls.
set(linux_bash_codegen_options
    --pre-RA-sched=fast
    --no-stack-slot-sharing
    --bpf-max-stores-per-memfunc=4096
    --bpf-expand-memcpy-in-order)

option(LINUX_BASH_DETAILED_DEBUG "Retain per-instruction source and local-variable debug records (slow)" OFF)
if(NOT LINUX_BASH_DETAILED_DEBUG)
    list(APPEND linux_bash_codegen_options --function-line-info)
endif()
list(APPEND linux_bash_codegen_options --save-temps)
