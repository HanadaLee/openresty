# Reuse the configured nginx compiler, flags and header search paths.
.PHONY: complex-value-fixture
complex-value-fixture:
	$(CC) $(CFLAGS) -fPIC $(ALL_INCS) $(FIXTURE_SOURCE) -shared -o $(FIXTURE_OUTPUT)
