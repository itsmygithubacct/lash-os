#pragma once
/* Picolibc uses __unused as an attribute; musl uses it as a padding field. */
#pragma push_macro("__unused")
#undef __unused
#include_next <mqueue.h>
#pragma pop_macro("__unused")
