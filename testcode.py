file = "/etc/passwd"
##for file in files_to_check:
command = "FILE=" + file
with open("script.sh", "w") as f:
     f.write("#!/bin/bash")
     f.write(command)
     f.write("if -w $FILE; then")
     f.write("\techo '$FILE is writeable'")
     f.write("fi")
