.PHONY: test scan rules clean

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

scan:
	./vulnscan scan . --no-color

rules:
	./vulnscan rules

clean:
	rm -rf reports __pycache__ src/vulnscan/__pycache__ src/vulnscan/rules/__pycache__ tests/__pycache__
