# Reuse the configured source tree's compiler, flags and header search paths.
# Invoke with: make -f objs/Makefile -f <this-file> abi-fixture ...
.PHONY: abi-fixture
abi-fixture:
	$(CC) $(CFLAGS) -fPIC -I$(ABI_TMP) $(ALL_INCS) $(ABI_FLAGS) $(ABI_SOURCE) $(ABI_LINK) -o $(ABI_OUTPUT)
