enc:
	@tar cvfz - src/main/resources/credentials*.yml | \
	openssl enc -aes-256-cbc -pbkdf2 \
	-out src/main/resources/credentials.tgz.enc
	ls -l src/main/resources/
dec:
	@openssl enc -d -aes-256-cbc -pbkdf2 \
	-in src/main/resources/credentials.tgz.enc | \
	tar xvfz -
	ls -l src/main/resources/
