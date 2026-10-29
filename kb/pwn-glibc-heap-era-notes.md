tags: pwn, heap, glibc, tcache, safe-linking

# glibc heap notes for recent CTF pwn (2.31 - 2.39 era)

* **tcache** (bins 0-63, sizes up to 0x410): first stop for any
  use-after-free / double-free. Poisoning: overwrite `next` to get malloc to
  return an arbitrary pointer.
* **safe-linking** (glibc >= 2.32): the stored `next` is
  `chunk_addr >> 12 ^ target` - leak the heap address first (unsorted bin or
  partial overwrite) or compute it from a known chunk.
* **double free**: tcache key check is trivial to pass in 2.31 (key = tcache
  pointer, just overwrite it); in 2.32+ key is the position, still bypassable
  with a UAF write.
* **unsorted bin leak**: free a chunk into unsorted, its fd/bk point to
  main_arena - classic libc leak; pair with `show` primitives.
* **house-of techniques**: fastbin attack for size-check targets; house of
  botcake for tcache+fastbin coexistence; FSOP via wide vtable still works on
  2.36+ but expects `_wide_data` setup - prefer exit-handlers when available.
* **hooks are gone** (removed in 2.34): __free_hook/__malloc_hook strategies
  are dead; target exit_funcs, FILE vtables, or ROP via arb write.

> AI生成
