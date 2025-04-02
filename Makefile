enc:
	openssl enc -aes-256-cbc -in src/main/resources/credentials.yml -out src/main/resources/credentials.yml.enc -pbkdf2
dec:
	openssl enc -d -aes-256-cbc -in src/main/resources/credentials.yml.enc -out src/main/resources/credentials.yml -pbkdf2

