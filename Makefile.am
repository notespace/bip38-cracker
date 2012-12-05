INCLUDES = @GLIB_CFLAGS@ -Ipicocoin/include -Iscrypt/util -Iscrypt/crypto -Iscrypt -O0 -g

bin_PROGRAMS = cracker

cracker_SOURCES= \
	main.c \
	scrypt/crypto/crypto_scrypt-ref.c \
	scrypt/crypto/sha256.c

# choose either sse or non-sse (ref) for above. SSE gives some speedup.
#	scrypt/crypto/crypto_scrypt-sse.c
#	scrypt/crypto/crypto_scrypt-ref.c


cracker_LDADD = picocoin/lib/libccoin.a @GLIB_LIBS@ @CRYPTO_LIBS@ -lpthread
