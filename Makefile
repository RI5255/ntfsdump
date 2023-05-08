ntfsdump : ntfsdump.c 
	gcc -o $@ -Iinclude $^

clean:
	rm -f ntfsdump

.PHONY: clean