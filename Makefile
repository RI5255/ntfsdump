ntfsdump : ntfsdump.c 
	gcc -o $@ $^

clean:
	rm -f ntfsdump

.PHONY: clean