import time

FILE = "/var/log/dpkg.log"

while True:
    with open(FILE, "r") as f:
        contents = f.read()
    print(f"Length: {len(contents)}")
    time.sleep(5)
