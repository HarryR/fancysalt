all: debug release

debug: tweetnacl.c main.c
	gcc -o $@ $+

release: tweetnacl.c main.c
	gcc -flto -O3 -ffast-math -fomit-frame-pointer -o $@ $+
	strip -R .note -R .comment $@
	upx --ultra-brute $@

clean:
	rm -f derp debug release
